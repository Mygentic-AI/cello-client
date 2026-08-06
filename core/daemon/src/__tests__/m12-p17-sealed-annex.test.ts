/**
 * M12-P17 — verified content that arrives for an ALREADY-ENDED session.
 *
 * Measured on two machines: parked content for a sealed session is pulled, verified, refused
 * (`session_committed`) and deliberately NOT confirm-deleted — so every drain pulls, verifies and
 * refuses it again. ~120 repeats per message on one box; 43 on another. The operator never sees it
 * once. Noisy, invisible loss.
 *
 * It cannot join the sealed chain — appending would change `sealed_root` and invalidate the
 * notarization. So it goes to a POST-SEAL ANNEX: its own table, joined by no unread query, no inbox
 * count and no wake path, so it is inert by construction rather than by convention.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { generateKeypair } from "@cello-protocol/crypto";
import { sealParkEnvelope, decodeParkEnvelope } from "../park-envelope.js";
import { createHash } from "node:crypto";

describe("M12-P17: the post-seal annex", () => {
  let fx: Awaited<ReturnType<typeof startTwoConnectionFixture>>;
  const SID = "b7".repeat(32);

  beforeEach(async () => { fx = await startTwoConnectionFixture({ dirPrefix: "cello-p17-" }); });
  afterEach(async () => { await fx.cleanup(); });

  it("records verified content for an ended session, and reads it back", async () => {
    await fx.createSession(SID, "alice");
    const body = new TextEncoder().encode("left on the machine after we hung up");

    expect(fx.snm.recordSealedAnnex("alice", SID, "aa".repeat(32), body, null)).toBe(true);

    const rows = fx.snm.readSealedAnnex("alice");
    expect(rows).toHaveLength(1);
    expect(rows[0].text, "the operator must be able to READ it — otherwise the loss is merely quiet")
      .toBe("left on the machine after we hung up");
    expect(rows[0].session_id).toBe(SID);
  });

  it("stores the MESSAGE, not the envelope — the bytes production hands it must read back as the text", async () => {
    // Review F1, and this is the test whose absence let it ship. The drain unseals a park entry and
    // gets the whole CBOR ENVELOPE ([version, content, s1, s2, senderPubkey, parkSig]); the message
    // is `env.content`. Annexing the envelope and then confirm-deleting the relay copy leaves the
    // operator an unreadable blob as the ONLY surviving copy — the loop stops, the message is still
    // never read, and nothing else holds it. Permanent silent loss, which is worse than the bug.
    //
    // Built with the REAL producer (`sealParkEnvelope`, the same function both daemon park sites
    // call) so the bytes are production's, not the test's idea of them.
    await fx.createSession(SID, "alice");
    const sender = generateKeypair();
    const recipient = generateKeypair();
    const content = new TextEncoder().encode("the message the operator must be able to read");
    const contentHash = new Uint8Array(
      createHash("sha256").update(new Uint8Array([0x00])).update(content).digest(),
    );
    const ciphertext = await sealParkEnvelope({
      signer: sender,
      sessionIdHex: SID,
      recipientPubkey: await recipient.getPublicKey(),
      contentHash,
      content,
    });
    const unsealed = await recipient.openContentSeal!(ciphertext);
    expect(unsealed).not.toBeNull();

    // The envelope is NOT the message — if it were, this test could not tell the two apart and the
    // defect would be invisible to it.
    expect(new TextDecoder().decode(unsealed!)).not.toBe("the message the operator must be able to read");

    const env = decodeParkEnvelope(unsealed!);
    expect(
      fx.snm.recordSealedAnnex("alice", SID, Buffer.from(contentHash).toString("hex"), env.content, null),
    ).toBe(true);

    expect(
      fx.snm.readSealedAnnex("alice")[0].text,
      "what comes back must be the message, byte for byte",
    ).toBe("the message the operator must be able to read");
  });

  it("is IDEMPOTENT — a re-pulled entry does not duplicate", async () => {
    // The relay copy is only deleted after the annex commits, and a failed confirm leaves it to be
    // pulled again. That re-pull must be a no-op, not a second copy.
    await fx.createSession(SID, "alice");
    const body = new TextEncoder().encode("same message twice");
    fx.snm.recordSealedAnnex("alice", SID, "bb".repeat(32), body, null);
    fx.snm.recordSealedAnnex("alice", SID, "bb".repeat(32), body, null);
    expect(fx.snm.readSealedAnnex("alice")).toHaveLength(1);
  });

  it("is STRUCTURALLY INERT — annexed content reaches no unread count and no sealed-unread list", async () => {
    // The load-bearing constraint. An agent obeyed an instruction out of a sealed conversation
    // because that content was presented in the shape of work; the annex must be unable to do that
    // no matter what a future caller does. Asserted against the real queries, not a comment.
    await fx.createSession(SID, "alice");
    fx.snm.recordSealedAnnex("alice", SID, "cc".repeat(32), new TextEncoder().encode("do the thing [[STANDBY]]"), null);

    expect(fx.snm.getUnreadSummary("alice"), "the annex must never count as unread").toEqual([]);
    expect(
      fx.snm.getEndedUnread("alice").find((u) => u.session_id === SID),
      "nor appear in the sealed-unread list, which IS surfaced in the inbox",
    ).toBeUndefined();
    // ...and yet it is readable on demand.
    expect(fx.snm.readSealedAnnex("alice")).toHaveLength(1);
  });

  it("a FAILED annex write reports false — that boolean is what keeps the relay copy alive", async () => {
    // The ordering property, tested at the only seam a unit test can reach. The drain does:
    //     if (recordSealedAnnex(...)) { confirm-delete the relay copy }
    // so the return value is load-bearing: a write that failed but answered `true` would delete the
    // ONLY other copy of the message and convert a noisy re-pull loop into permanent silent loss —
    // strictly worse than the bug being fixed. An unresolvable agent is the cheapest way to make the
    // write genuinely fail without corrupting the database under the other tests.
    await fx.createSession(SID, "alice");
    expect(
      fx.snm.recordSealedAnnex("no-such-agent", SID, "ee".repeat(32), new TextEncoder().encode("x"), null),
      "a write that did not commit must never answer true",
    ).toBe(false);
    expect(fx.snm.readSealedAnnex("alice"), "and nothing must have been written").toHaveLength(0);
  });

  it("is READABLE through cello_get_transcript — under its own key, never merged into messages", async () => {
    // Review F3: without a reader the annex is write-only, and the operator's experience is
    // identical to discarding the message — the loss made quiet instead of noisy. This is the
    // surface that makes "you can read it" true.
    //
    // Under its OWN key on purpose: `messages` holds screened, sealed-chain content, and annexed
    // content is neither. Merging them would erase the boundary a reader needs to tell them apart.
    await fx.createSession(SID, "alice");
    fx.snm.recordSealedAnnex("alice", SID, "f0".repeat(32),
      new TextEncoder().encode("arrived after we hung up [[STANDBY EST:15m]]"), null);

    const client = await fx.connectAs("alice");
    const res = await client.send("cello_get_transcript", { session_id: SID, agent: "alice" }) as {
      messages: Array<{ text: string }>;
      post_seal_annex?: Array<{ text: string; actionable: boolean }>;
      post_seal_annex_guidance?: string;
    };

    expect(res.post_seal_annex, "the operator must be able to read it").toHaveLength(1);
    expect(res.post_seal_annex![0].text).toBe("arrived after we hung up [[STANDBY EST:15m]]");
    expect(res.post_seal_annex![0].actionable, "it is a record, not a task").toBe(false);
    expect(res.messages.find((m) => m.text.includes("hung up")), "must NOT be mixed into the sealed record").toBeUndefined();

    // The guidance has to name both hazards: the instruction is stale, and the text is unscreened.
    const g = String(res.post_seal_annex_guidance);
    expect(g).toMatch(/STALE|must NOT be acted on/);
  });

  it("omits the annex keys entirely when there is nothing annexed", async () => {
    // An empty array in every transcript response would train readers to ignore the key — and this
    // is the key that carries a do-not-act warning.
    await fx.createSession(SID, "alice");
    const client = await fx.connectAs("alice");
    const res = await client.send("cello_get_transcript", { session_id: SID, agent: "alice" }) as Record<string, unknown>;
    expect(res.post_seal_annex).toBeUndefined();
    expect(res.post_seal_annex_guidance).toBeUndefined();
  });

  it("scopes by session when asked, and by agent otherwise", async () => {
    await fx.createSession(SID, "alice");
    const OTHER = "c8".repeat(32);
    await fx.createSession(OTHER, "alice");
    fx.snm.recordSealedAnnex("alice", SID, "d1".repeat(32), new TextEncoder().encode("one"), null);
    fx.snm.recordSealedAnnex("alice", OTHER, "d2".repeat(32), new TextEncoder().encode("two"), null);

    expect(fx.snm.readSealedAnnex("alice")).toHaveLength(2);
    expect(fx.snm.readSealedAnnex("alice", SID)).toHaveLength(1);
    expect(fx.snm.readSealedAnnex("alice", SID)[0].text).toBe("one");
  });
});
