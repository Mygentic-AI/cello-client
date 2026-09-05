/**
 * DOD-M15-KEYAGREE-1 — the key's LIFECYCLE in the daemon (006-CRYPTO, part 2).
 *
 * ─── What this half is, and what it deliberately is not ────────────────────────────────────────
 *
 * The key agreement itself was written, reviewed and tested, and **nothing called it**: no code
 * minted a session ephemeral, none destroyed one, and no message was encrypted. A reviewed library
 * with a header claiming forward secrecy and no caller is exactly the shape this milestone exists to
 * catch, so this half wires the LOCAL lifecycle — mint at open, hold in memory only, destroy at
 * close — and says so on the session where a reader can see it.
 *
 * **The exchange is NOT here.** Sending the public half, signing it, verifying the peer's and
 * encrypting content with the agreed secret are `007-CRYPTO`, and they are one wire format that
 * ships together. So these tests assert a keypair that exists, stays put, and is gone afterwards.
 *
 * ─── Why "in memory only" gets a test rather than a comment ────────────────────────────────────
 *
 * Forward secrecy is not a property of minting a fresh key; it is a property of the old one being
 * GONE. Persisting the secret would void it permanently, silently, and for every session already in
 * the database — and it is the single easiest thing for a later change to do by accident, because
 * every other piece of session state around it IS persisted. The salt is deliberately persisted; the
 * contribution is deliberately not; this is deliberately not. A test is the only thing that keeps
 * those three apart.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { generateSessionEphemeral } from "@cello-protocol/crypto";

const SID = "7c".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";

describe("006-CRYPTO: the throwaway key is minted once, held in memory, and destroyed", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ opening a session mints exactly ONE keypair", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-mint-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const minted = fx.eventsNamed("session.ephemeral.minted");
    expect(minted.length, "a session that is active must have a key, and exactly one").toBe(1);
    expect(
      String(minted[0]!.ctx!["sessionId"]),
      "and it must be attributed to the session it belongs to",
    ).toBe(SID);
  }, 60_000);

  it("★★ RE-ENTERING the activation path does NOT mint a second keypair", async () => {
    /**
     * ⚠️ THIS TEST EXISTS BECAUSE A MUTATION PROVED THE LAST ONE DID NOT COVER IT. Deleting the
     * idempotence guard left every test green: "opening a session mints exactly one" only ever calls
     * the mint path ONCE, so it cannot tell an idempotent mint from one that overwrites.
     *
     * A reconnect can re-enter an activation path. Minting a second keypair there would leave the
     * two sides deriving against a moving value, and the symptom — a session that reconnects and
     * still cannot agree — reads as a network fault rather than as a bug here.
     *
     * Asserts the VALUE is unchanged, not just that the count stayed at one: an implementation that
     * replaced the keypair and logged nothing would satisfy a count.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-once-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const first = fx.snm.sessionEphemeralPublicForTest("alice", SID);
    expect(first, "PRECONDITION: a keypair exists to be preserved").not.toBeNull();

    fx.snm.mintSessionEphemeralForTest("alice", SID);

    const second = fx.snm.sessionEphemeralPublicForTest("alice", SID);
    expect(
      Buffer.from(second!).toString("hex"),
      "a second keypair replaced the first mid-session; the peer is now holding a public half we no longer have the secret for",
    ).toBe(Buffer.from(first!).toString("hex"));
    expect(
      fx.eventsNamed("session.ephemeral.minted").length,
      "and it must not even claim to have minted twice",
    ).toBe(1);
  }, 60_000);

  it("★★ the HAND-OFF path mints too — an inbound session is as new as an outbound one", async () => {
    /**
     * Activation path 2 of 3, and it had no test (review pass 2, finding 6): every other test here
     * goes through `createSession`, so deleting the mint from `acceptSession` left the whole suite
     * green. A session promoted out of the standing receiver would then be active with no key and
     * nothing saying so — the exact "missed path" this clause is written against.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-handoff-" });
    await fx.snm.ensureStandingReceiverForAgent("alice");

    const accepted = await fx.snm.acceptSession(
      "e1".repeat(32), "alice", "cc".repeat(32), "initiator-peer", "corr-handoff",
    );
    expect(accepted, "PRECONDITION: the hand-off actually happened").toBeTruthy();

    expect(
      fx.snm.sessionEphemeralPublicForTest("alice", "e1".repeat(32)),
      "a session accepted from the standing receiver has no key — the hand-off path does not mint",
    ).not.toBeNull();
  }, 60_000);

  it("★ the log NEVER carries the secret — only a prefix of the PUBLIC half", async () => {
    /**
     * A secret in a log line is a secret on disk, in a support bundle, and in whatever ships a log
     * off the machine. The event exists so two daemons can be correlated, which needs an identifier
     * and not a value.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-log-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const ctx = fx.eventsNamed("session.ephemeral.minted")[0]!.ctx!;
    expect(Object.keys(ctx)).not.toContain("secretKey");
    expect(Object.keys(ctx)).not.toContain("privateKey");
    const printed = String(ctx["publicKeyPrefix"] ?? "");
    expect(printed, "an 8-byte prefix, so it identifies without publishing the key").toHaveLength(16);
  }, 60_000);

  it("★★ the secret is in MEMORY ONLY — it is absent from every column of the session row", async () => {
    /**
     * The clause that protects forward secrecy from a later, well-meaning change. Asserted against
     * the DATABASE rather than against an accessor, because an accessor that hides the value proves
     * nothing about what a backup contains.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-nodisk-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const db = fx.snm.getDb()!;
    const row = db.prepare("SELECT * FROM sessions WHERE session_id = ?").get(SID) as Record<string, unknown>;
    expect(row, "PRECONDITION: the session row exists, or this test proves nothing").toBeTruthy();

    /**
     * A TRIPWIRE, AND ITS LIMITS ARE STATED SO IT IS NOT READ AS COMPLETE. It scans every column of
     * the `sessions` row, so a migration adding `session_ephemeral_secret` fails it rather than
     * slipping past a test that only knew the columns of its own era. It does NOT cover a persist to
     * a different table, or a hex-`TEXT` column named none of these words.
     *
     * `content_salt` is exempt BY NAME, with a reason: it is 32 bytes and it is SUPPOSED to be on
     * disk — opposite lifetime, deliberately (the salt must survive the session, this secret must
     * not). Without the exemption this test goes red about the throwaway key the moment anything
     * agrees a salt in this fixture, for a reason that has nothing to do with it.
     */
    const PERSISTED_ON_PURPOSE = new Set(["content_salt", "genesis_prev_root"]);
    /**
     * ⚠️ **EVERY NAME ADDED HERE WEAKENS THE LENGTH TRIPWIRE, so each one pays for itself with a
     * POSITIVE assertion rather than just an exemption.**
     *
     * `genesis_prev_root` (033-ACKEMIT) is 32 bytes and belongs on disk for the same shape of reason
     * `content_salt` does — opposite lifetime to the throwaway secret, which must not survive the
     * session while this must. But it is also a PUBLIC derived value, so unlike the salt it can be
     * checked directly: asserting it equals the value the fixture agreed proves it is not key
     * material, which is what the length heuristic was only ever approximating.
     */
    const genesis = row["genesis_prev_root"];
    expect(genesis, "PRECONDITION: the fixture agreed a genesis, or this assertion proves nothing").toBeTruthy();
    expect(
      Buffer.from(genesis as Uint8Array).equals(Buffer.alloc(32, 0x9c)),
      "the genesis column holds the session's agreed starting point — a public value — and not key material",
    ).toBe(true);
    for (const [column, value] of Object.entries(row)) {
      if (PERSISTED_ON_PURPOSE.has(column)) continue;
      expect(
        /ephemeral|secret|private/i.test(column),
        `column '${column}' looks like it holds key material; the throwaway secret must never be persisted`,
      ).toBe(false);
      if (value instanceof Uint8Array) {
        expect(
          value.length,
          `column '${column}' holds 32 bytes — check it is not the throwaway secret, which must never reach disk`,
        ).not.toBe(32);
      }
    }
  }, 60_000);

  it("★★ closing the session DESTROYS the secret", async () => {
    /**
     * Forward secrecy is the old key being gone. `destroySessionEphemeral` zeroes the buffer we hold
     * before the entry is dropped — dropping alone would leave the bytes wherever the collector last
     * moved them.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-destroy-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    expect(fx.eventsNamed("session.ephemeral.minted").length).toBe(1);

    // A keypair THIS TEST owns, so the buffer can be inspected after the daemon is done with it.
    // Asserting the event alone would pass for an implementation that logs and never overwrites.
    const mine = generateSessionEphemeral();
    fx.snm.setSessionEphemeralForTest("alice", SID, mine);
    expect(mine.secretKey.some((b) => b !== 0), "PRECONDITION: a real secret to destroy").toBe(true);

    await fx.snm.destroySessionNode("alice", SID, "sealed");

    expect(
      fx.eventsNamed("session.ephemeral.destroyed").length,
      "the session ended and its key outlived it",
    ).toBe(1);
    expect(
      mine.secretKey.every((b) => b === 0),
      "the entry was dropped without ZEROING it — the bytes are still wherever the collector left them",
    ).toBe(true);
  }, 60_000);

  it("★★ SHUTDOWN zeroes every live session's secret, not just the map", async () => {
    /**
     * The transport seeds are zeroed four lines above this in `gracefulShutdown`, for a reason that
     * applies identically: shutdown marks rows `interrupted` by direct SQL, so no per-session
     * teardown fires, and this process is known to linger — a `cello logout` was measured still
     * alive 30+ seconds later.
     *
     * ⚠️ THIS TEST EXISTS BECAUSE THE MUTANT SURVIVED. Deleting the `destroySessionEphemeral` call
     * and keeping `.clear()` passed everything: the map was empty either way, so every presence
     * assertion held while the secrets stayed in memory. Only a reference the test owns can tell
     * the two apart.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-shutdown-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const mine = generateSessionEphemeral();
    fx.snm.setSessionEphemeralForTest("alice", SID, mine);
    expect(mine.secretKey.some((b) => b !== 0), "PRECONDITION: a real secret to destroy").toBe(true);

    await fx.snm.gracefulShutdown();

    expect(
      mine.secretKey.every((b) => b === 0),
      "the daemon shut down and left a live session's secret in memory for as long as the process lingers",
    ).toBe(true);
  }, 60_000);

  it("★★ the key SURVIVES while a seal is in flight — it is not destroyed early", async () => {
    /**
     * ⚠️ REPLACES AN ORDERING TEST THAT PROVED NOTHING (review pass 2, finding 4). It asserted
     * `session.ephemeral.destroyed` came before `session.node.destroyed` — two log lines two
     * statements apart in the same function, with nothing between them. The order was guaranteed by
     * adjacency and said nothing about the seal, so moving the destroy to the TOP of the close
     * handler, before the ceremony even started, passed it.
     *
     * What the clause actually requires is that the key is still there while the seal needs the
     * session. So that is what this asserts: with a ceremony genuinely in flight, the key is
     * present — and only once the session is torn down is it gone.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-order-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    fx.markSealInFlightForTest("alice", SID);
    expect(
      fx.snm.sessionEphemeralPublicForTest("alice", SID),
      "a seal is in flight and the key is already gone — destroying it before the ceremony finishes is the failure this clause names",
    ).not.toBeNull();

    await fx.snm.destroySessionNode("alice", SID, "sealed");
    expect(
      fx.snm.sessionEphemeralPublicForTest("alice", SID),
      "and once the session is over it must be gone",
    ).toBeNull();
    expect(fx.eventsNamed("session.ephemeral.destroyed").length).toBe(1);
  }, 60_000);

  it("★★ an INTERRUPTED session destroys its key — the path that used to keep it for hours", async () => {
    /**
     * Review pass 2, finding 2, and it was the common path rather than a corner. A relay blip or a
     * sleeping laptop is the ordinary way a session ends badly: `markInterruptedWithDetails` drops
     * the node and deliberately does NOT evict the caches, because buffered plaintext has to stay
     * drainable and the park timers have to stay armed. The destroy rode the eviction, so it never
     * ran — and when that session later sealed, `destroySessionNode` returned at its
     * `if (!entry) return` and never evicted either. The receipt landed, the session was over, and
     * the secret was still resident until the process exited.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-interrupt-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    expect(fx.snm.sessionEphemeralPublicForTest("alice", SID)).not.toBeNull();

    await fx.snm.markInterruptedWithDetails("alice", SID, 0, "stream_close");

    expect(
      fx.snm.sessionEphemeralPublicForTest("alice", SID),
      "the session was interrupted and its key outlived it — on a long-lived daemon, until the process exits",
    ).toBeNull();
  }, 60_000);

  it("★★ a REVIVED session RE-KEYS — it does not resume on the old secret", async () => {
    /**
     * Decisions Carried #5, and it was asserted in three comments while being false. Revival
     * requires status `interrupted`, and that path kept the key — so `#mintSessionEphemeral` found
     * one already present and the idempotence guard silently preserved it. A session interrupted at
     * 09:15 and revived at 17:00 resumed on a key that had been resident for eight hours across a
     * laptop sleep, with nothing anywhere recording that it had not re-keyed.
     *
     * Asserts the public half CHANGED. "A key exists afterwards" is satisfied by the stale one.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-rekey-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    const before = fx.snm.sessionEphemeralPublicForTest("alice", SID);
    expect(before, "PRECONDITION: a key to re-key away from").not.toBeNull();

    await fx.snm.markInterruptedWithDetails("alice", SID, 0, "stream_close");
    await fx.snm.reviveSessionNode("alice", SID);

    const after = fx.snm.sessionEphemeralPublicForTest("alice", SID);
    expect(after, "the revived session has no key at all").not.toBeNull();
    expect(
      Buffer.from(after!).toString("hex"),
      "the revived session resumed on the OLD secret instead of re-keying",
    ).not.toBe(Buffer.from(before!).toString("hex"));
  }, 60_000);
});

describe("006-CRYPTO: the session SAYS it is not encrypted rather than leaving it to be assumed", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★★ a session reports that CELLO is not encrypting its content, with usable guidance", async () => {
    /**
     * The anti-"reads as done" clause, and it is the reason this half exists at all: the key
     * agreement shipped with tests, a public header claiming forward secrecy, and no caller, and
     * nothing anywhere said so. Silence is what made that survivable.
     *
     * ⚠️ THIS ASSERTS THE DAEMON RECORD, AND THAT IS ONLY HALF THE PROPERTY. An earlier version of
     * this docblock claimed it asserted the agent-facing payload; it did not, and deleting the whole
     * whitelist entry in `session-read-handlers.ts` left this file green — the no-reader defect,
     * committed for a fourth time inside the fix for it.
     *
     * The agent-facing half is asserted through the socket in
     * `dod-m15-refused-inbound-silent-1.test.ts`, next to the salt test it should have been copied
     * from. This one keeps the record-level check, which is still worth having: it is what fails if
     * `#saltStatusOf` stops stamping the field at all.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-status-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    // The fixture seeds an agreed key, because that is the production state and a live send needs
    // one. Assert BOTH directions from here, so this cannot pass by the field being stuck either way.
    const agreed = fx.snm.getSessionsForAgent("alice").find((s) => s.session_id === SID);
    expect(agreed?.["content_encrypted"], "a session with an agreed key is encrypted").toBe(true);
    expect(
      agreed?.["content_encryption_reason"],
      "and a session that IS encrypted carries no reason — absence is the healthy case",
    ).toBeUndefined();

    // Now take the key away, exactly as a teardown does, and the same surface must say so.
    fx.snm.forgetSessionContentKeyForTest("alice", SID);
    const row = fx.snm.getSessionsForAgent("alice").find((s) => s.session_id === SID);
    expect(
      row?.["content_encrypted"],
      "with no agreed key this cannot be true — a hardcoded field would not notice",
    ).toBe(false);
    expect(
      String(row?.["content_encryption_reason"] ?? ""),
      "and the reason must be a named code, not an empty field",
    ).toBe("not_yet_agreed");
  }, 60_000);

  it("★ every reason names a verb the reader can perform, and none calls a fault expected", async () => {
    /**
     * The guidance map is TOTAL over the reason union, so the type enforces that a reason cannot be
     * added without something to do about it. What the type cannot enforce is that the text is USEFUL,
     * which is the half that decays.
     *
     * ⚠️ NONE of these may read as reassurance. Every one is a fault — local, transient, or a
     * counterparty that did not finish an exchange it is running the code for. There is no
     * "your counterparty is on an older build" case, because there are no older builds.
     */
    const { CONTENT_ENCRYPTION_GUIDANCE, CONTENT_ENCRYPTION_REASONS } =
      await import("../content-encryption-status.js");

    for (const reason of Object.values(CONTENT_ENCRYPTION_REASONS)) {
      const text = CONTENT_ENCRYPTION_GUIDANCE[reason];
      expect(text.length, `${reason} has no guidance`).toBeGreaterThan(60);
      expect(
        text,
        `${reason} tells the reader a fault is expected — none of these is a steady state`,
      ).not.toMatch(/this is expected|nothing is wrong with (either|both)|no setting that turns/i);
      expect(
        text,
        `${reason} blames a build version; there are no other builds`,
      ).not.toMatch(/predates|older build|upgrade/i);
    }
  });

  it("★ a LOCAL fault points at this machine, and a peer fault does not", async () => {
    // The substitution this closed set exists to end: an operator whose own machine cannot sign
    // being sent to raise it with a counterparty that did nothing.
    const { CONTENT_ENCRYPTION_GUIDANCE, CONTENT_ENCRYPTION_REASONS } =
      await import("../content-encryption-status.js");

    const local = CONTENT_ENCRYPTION_GUIDANCE[CONTENT_ENCRYPTION_REASONS.NO_LOCAL_IDENTITY];
    expect(local).toMatch(/THIS machine/i);
    expect(local, "it must say plainly that the counterparty is not involved").toMatch(/counterparty did nothing/i);

    const ours = CONTENT_ENCRYPTION_GUIDANCE[CONTENT_ENCRYPTION_REASONS.OUR_ANNOUNCE_FAILED];
    expect(ours, "our own failed send must not be raised with them").toMatch(/do not raise it with them/i);
  });
});
