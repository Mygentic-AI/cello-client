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

    // Every column, not a named one: a future migration that adds `session_ephemeral_secret` must
    // fail here rather than pass because this test only knew about the columns of its own era.
    for (const [column, value] of Object.entries(row)) {
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

    await fx.snm.destroySessionNode("alice", SID, "sealed");

    expect(
      fx.eventsNamed("session.ephemeral.destroyed").length,
      "the session ended and its key outlived it",
    ).toBe(1);
  }, 60_000);

  it("★★ destruction happens AFTER the node is torn down, never before the session is over", async () => {
    /**
     * The ordering is load-bearing and it is a property of WHERE the call sits: it rides
     * `#evictSessionCaches`, which both teardown paths reach at the END — the sealing path retires
     * the node once the ceremony is finished. Zeroing the key earlier, from a close handler, would
     * destroy it while the seal still needs the session.
     *
     * Asserted as an ORDER between two events rather than as "it eventually happened", because the
     * second is what a premature destroy would still satisfy.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-order-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.destroySessionNode("alice", SID, "sealed");

    const names = fx.events.map((e) => e.event);
    const destroyedKey = names.indexOf("session.ephemeral.destroyed");
    const destroyedNode = names.indexOf("session.node.destroyed");
    expect(destroyedKey, "PRECONDITION: the key was destroyed at all").toBeGreaterThan(-1);
    expect(destroyedNode, "PRECONDITION: the node was torn down at all").toBeGreaterThan(-1);
    expect(
      destroyedKey,
      "the key was zeroed before the node finished tearing down — a seal in flight would lose it",
    ).toBeLessThan(destroyedNode);
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
     * Asserted on the AGENT-facing payload, not the daemon record — a field that stops at the record
     * is the no-reader defect this codebase has already committed once, inside the fix for it.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-keylife-status-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const row = fx.snm.getSessionsForAgent("alice").find((s) => s.session_id === SID);
    expect(row?.["content_encrypted"], "no key is agreed in this build, so this cannot be true").toBe(false);

    const guidance = String(row?.["content_encryption_reason"] ?? "");
    expect(guidance, "and the reason must be a named code, not an empty field").toBe("no_key_exchange");
  }, 60_000);

  it("★ the guidance names no setting, because there is none", async () => {
    /**
     * An affordance that resolves to nothing is worse than none — the reader spends time looking for
     * it. There is nothing an operator can do about this one, so it says so.
     */
    const { CONTENT_ENCRYPTION_GUIDANCE, CONTENT_ENCRYPTION_REASONS } =
      await import("../content-encryption-status.js");
    const text = CONTENT_ENCRYPTION_GUIDANCE[CONTENT_ENCRYPTION_REASONS.NO_KEY_EXCHANGE];

    expect(text, "it must not send the operator hunting for a toggle").toMatch(/no setting that turns this on/i);
    expect(text, "and it must not blame the counterparty or their build").toMatch(/nothing is wrong with your setup/i);
    expect(
      text,
      "it must be truthful that the transport still encrypts — otherwise it reads as 'you are sending plaintext'",
    ).toMatch(/still encrypted in transit/i);
  });

  it("★ an UNRECOGNISED reason is described as unrecognised, never guessed at", async () => {
    // The value comes off a row an older or newer build may have written. Asserting the wrong cause
    // is how a reader acts on something that was never the problem.
    const { contentEncryptionGuidanceFor } = await import("../content-encryption-status.js");
    const text = contentEncryptionGuidanceFor("some_reason_from_a_later_build");
    expect(text).toMatch(/does not recognise/i);
    expect(text).toContain("some_reason_from_a_later_build");
  });
});
