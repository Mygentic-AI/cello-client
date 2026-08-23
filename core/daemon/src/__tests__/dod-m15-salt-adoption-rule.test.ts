/**
 * A SALT IS ADOPTED ONLY BEFORE THE FIRST LEAF — `DOD-M15-SEALWIRE-1` bullet 6, part B2b-2.
 * Decisions Carried #8: *"Agreed at session open, BEFORE the first leaf is hashed. Every leaf uses
 * the same salt."*
 *
 * ─── Why this guard has to exist BEFORE salting turns on, not alongside it ─────────────────────
 *
 * Once `contentHashForSession` consults the salt, "is this session salted?" is answered fresh on
 * every send. A salt that arrives *after* messages have already been hashed therefore splits the
 * transcript down the middle: leaves 1–3 unsalted, leaves 4+ salted, one session, no marker saying
 * where the change happened.
 *
 * That is exactly the failure Decision #8 forbids, and it is worse than the correlation weakness the
 * salt exists to fix — a half-salted transcript cannot be verified by either rule.
 *
 * **The rule is what removes the need for a schema change.** Without it, "salted or not" would have
 * to be a durable per-session flag with its own column, its own migration, and its own entry in the
 * rebuild DDL (which is where this milestone has now lost data twice). With it, the question is
 * decided once and answered by `content_salt IS NULL` forever after.
 *
 * ─── The counterbalance, named before the code ────────────────────────────────────────────────
 *
 * Refusing a salt is not free: a session that fails to adopt one is a session with a weaker content
 * hash for its whole life. That is the RIGHT trade — an unsalted transcript is exactly as verifiable
 * as every transcript in existence today, whereas a split one is verifiable by nobody — but it must
 * be LOUD, because silently declining a protection is how this milestone's other defects looked.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";
import * as lp from "it-length-prefixed";

const SID = "9c".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const PEER_HALF = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x6a);
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function saltFrame(): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement", session_id: SID, contribution: PEER_HALF,
  }) as Uint8Array).subarray();
}

function storedSalt(fx: TwoConnectionFixture): Uint8Array | null {
  const agentId = (fx.snm.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get("alice") as { agent_id: string }).agent_id;
  const row = fx.snm.getDb()
    .prepare("SELECT content_salt FROM sessions WHERE agent_id = ? AND session_id = ?")
    .get(agentId, SID) as { content_salt: Uint8Array | null } | undefined;
  return row?.content_salt ? new Uint8Array(row.content_salt) : null;
}

describe("Decision #8: the salt is adopted before the first leaf, or not at all", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a salt agreed BEFORE any leaf is adopted — the normal case must keep working", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-a-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: no leaves yet").toBe(0);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(200);

    expect(storedSalt(fx), "a salt agreed at session open must be adopted").not.toBeNull();
  }, 60_000);

  it("★ a salt arriving AFTER a leaf is REFUSED — it would split the transcript", async () => {
    /**
     * The whole point. Leaves 1..n are already hashed under the unsalted rule; adopting now would
     * hash n+1.. under a different one, in one session, with nothing recording where the change
     * happened. Neither half can then be verified by a single rule.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-b-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.seedReceived("alice", SID, "a message that is already hashed");
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: the session has a leaf").toBeGreaterThan(0);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    expect(
      storedSalt(fx),
      "adopting a salt after the first leaf splits the transcript — half verifiable by one rule, half by another",
    ).toBeNull();
  }, 60_000);

  it("★ the refusal is LOUD and says what the session loses, not just that it declined", async () => {
    /**
     * Silently declining a protection is how this milestone's other defects looked. The operator has
     * to be able to tell "this session is unsalted" from "this session failed to become salted", and
     * the second is the one that says something about their build or their counterparty.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-c-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.seedReceived("alice", SID, "already hashed");

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    const refused = fx.eventsNamed("session.salt.adoption.refused");
    expect(refused.length, "declining a protection must be announced").toBe(1);
    expect(refused[0]!.ctx!.leafCount, "and must say how far in the session already was").toBeGreaterThan(0);
    expect(
      String(refused[0]!.ctx!.impact),
      "it must say the session stays unsalted for its LIFE, not merely that this attempt failed",
    ).toMatch(/for the life of|remains unsalted|stays unsalted/i);
  }, 60_000);

  it("★ the session STAYS usable — refusing the salt must not refuse the conversation", async () => {
    /**
     * The counterbalance. An unsalted transcript is exactly as verifiable as every transcript in
     * existence today; a frozen session is not a conversation. Getting this backwards would trade a
     * correlation weakness for a broken product, which is the wrong direction on every axis.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-d-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.seedReceived("alice", SID, "already hashed");

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    expect(fx.eventsNamed("session.salt.frozen").length, "a refused adoption must NOT freeze the session").toBe(0);
    const revived = await fx.snm.reviveSessionNode("alice", SID);
    expect(
      (revived as { reason?: string }).reason ?? "",
      "and the session must still be revivable — this is a weaker hash, not a broken conversation",
    ).not.toMatch(/frozen/);
  }, 60_000);
});
