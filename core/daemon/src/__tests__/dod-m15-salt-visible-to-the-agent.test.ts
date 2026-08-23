/**
 * THE AGENT CAN SEE WHETHER ITS CONVERSATION IS PROTECTED — `DOD-M15-SEALWIRE-1` bullet 6, and the
 * invariant-2 gap the DoD recorded while building the adoption rule.
 *
 * ─── The invariant, and the half that was missing ──────────────────────────────────────────────
 *
 * *Failures must be loud in the LOG **and** in the agent response — never one instead of the other.*
 *
 * B2b-2 turned salting on. A session that cannot agree a salt falls back to the hashing every
 * shipped build uses and logs `session.content.unsalted` once, with its reason and its guidance.
 * That is the log half, and it is thorough. The agent response half did not exist at all: an
 * operator reading tool output — which is all an agent ever reads — had **no way to tell a protected
 * conversation from an unprotected one.**
 *
 * ─── Why a FIELD and not an event ──────────────────────────────────────────────────────────────
 *
 * The DoD ruled this deliberately, and it is worth restating because the instinct is to alert:
 *
 * > The bar is a field, not an event: the session's own status says whether its content hashes are
 * > salted. That is checkable, costs nothing per message, and cannot become a flood.
 * > **Deliberately NOT urgent.** An unsalted session is exactly as verifiable as every session
 * > shipped before the feature existed. This is the difference between *knowing* and *working*.
 *
 * ─── And why it is present on EVERY row, including the true one ────────────────────────────────
 *
 * This list's convention is present-only-when-interesting (`sealing`, `frontierMismatch`), and this
 * field breaks it on purpose. Those two say *something is happening*, so absence correctly means
 * nothing is. This says *what protects this conversation* — and for that, absence is unreadable: a
 * missing field on an older daemon and a missing field meaning "unprotected" look identical.
 *
 * That is the same collapse Decision #15 spends an entire wire discriminator preventing (ABSENT ⇒
 * legacy, NAMED ⇒ verify). A security property must never be inferable from a gap.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";
import * as lp from "it-length-prefixed";

const SALTED = "1a".repeat(32);
const UNSALTED = "2b".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function saltFrame(sessionId: string): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement",
    session_id: sessionId,
    contribution: new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x3e),
  }) as Uint8Array).subarray();
}

type Entry = { sessionId: string; contentSalted?: boolean };

async function listSessions(fx: TwoConnectionFixture): Promise<Entry[]> {
  const client = await fx.connectAs("alice");
  try {
    const res = (await client.send("cello_list_sessions", { filter: "all", limit: 50 })) as { sessions: Entry[] };
    return res.sessions;
  } finally {
    client.close();
  }
}

describe("DOD-M15-SEALWIRE-1: an agent can see whether its conversation is protected", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a SALTED session says so, and an UNSALTED one says so — in the same listing", async () => {
    /**
     * Both in one assertion pass on purpose. A field that is always `true`, or always `false`, is
     * satisfied by a constant — and a constant is exactly what a hurried implementation produces.
     * Two sessions in one response, differing only in whether their salt agreement completed, is
     * what makes the field mean something.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-visible-" });
    await fx.createSession(SALTED, "alice", "bobpubkeyhex", PEER);
    await fx.createSession(UNSALTED, "alice", "bobpubkeyhex", PEER);

    // Only one of them reaches an agreement.
    await fx.snm.handleContentFrameForTest("alice", SALTED, saltFrame(SALTED), PEER);
    await wait(250);

    const sessions = await listSessions(fx);
    const salted = sessions.find((s) => s.sessionId === SALTED);
    const unsalted = sessions.find((s) => s.sessionId === UNSALTED);

    expect(salted, "precondition: both sessions must be listed").toBeDefined();
    expect(unsalted, "precondition: both sessions must be listed").toBeDefined();
    expect(
      salted!.contentSalted,
      "a session that agreed a salt must report itself protected — otherwise the operator cannot tell the feature is working at all",
    ).toBe(true);
    expect(
      unsalted!.contentSalted,
      "and one that did not must report itself unprotected — this is the whole point of the field",
    ).toBe(false);
  }, 60_000);

  it("★ the field is PRESENT on every row — absence must never be how 'unprotected' is expressed", async () => {
    /**
     * ⚠️ THE ASSERTION THAT KEEPS THIS FROM DECAYING INTO THE LIST'S OTHER CONVENTION.
     *
     * `sealing` and `frontierMismatch` are omitted when false, which is right for them: they report
     * that something is happening. If someone "tidies" this field to match, then a daemon too old to
     * have it and a session that is genuinely unprotected become indistinguishable to every reader —
     * and the reader has no way to know which it is looking at.
     *
     * `toBe(false)` above would still pass if the key were dropped and the value read as
     * `undefined`… no: `undefined` is not `false`. But `in` is what states the requirement, rather
     * than relying on a strict-equality accident to enforce it.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-present-" });
    await fx.createSession(UNSALTED, "alice", "bobpubkeyhex", PEER);

    const sessions = await listSessions(fx);
    for (const s of sessions) {
      expect(
        "contentSalted" in s,
        "an absent field and an unprotected session must not look the same — that is the collapse the wire discriminator exists to prevent",
      ).toBe(true);
      expect(typeof s.contentSalted, "and it must be a boolean, not a string or a null").toBe("boolean");
    }
  }, 60_000);
});
