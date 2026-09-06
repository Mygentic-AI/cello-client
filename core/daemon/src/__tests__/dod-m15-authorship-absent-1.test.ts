/**
 * DOD-M15-AUTHORSHIP-ABSENT-1 — no passport, no entry.
 *
 * ─── The failure, from the operator's chair ────────────────────────────────────────────────────
 *
 * A message arrives carrying a signature that does not match your counterparty's key, and the
 * conversation freezes — correctly. A message arrives carrying NO signature at all, and it is
 * shown to you and written into the record as though it had been checked. Andre, on being shown
 * it: *"I show up with my passport and the photo doesn't match, I'm blocked. But if I arrive at
 * immigration with no passport, they let me through."*
 *
 * What it costs is the thing the receipt is for: you could prove who wrote MOST lines of a
 * transcript, and "most" is not a receipt. Any party that passed the peer gate could opt out of
 * being attributable by simply omitting the field.
 *
 * ─── The two halves, and why the second one is the careless-fix trap ───────────────────────────
 *
 * The signature was only ever delivered inside the RELAY's Structure 2, so refusing on its absence
 * would have made the relay a precondition for reading your mail. That reasoning was sound and it
 * stopped one field short: `hash_submit` has always carried `structure1_cbor` and
 * `sender_signature` as two separate top-level fields, so the signature never needed the relay.
 *
 *   1. IDENTITY IS MANDATORY. No usable authorship proof ⇒ refused by name, not ingested.
 *   2. POSITION STAYS SOFT. A valid signature with NO `structure2_cbor` is ACCEPTED and falls back
 *      to the witness stream. This is the case the original design was protecting, and the one a
 *      careless fix ("just make Structure 2 mandatory") breaks.
 *
 * Both are asserted here. A fix that satisfies (1) by breaking (2) reddens the second describe.
 */

import { describe, it, expect, afterEach } from "vitest";
import { encodeCbor, encodeStructure1 } from "@cello-protocol/protocol-types";
import { generateKeypair, sealSessionContent, verify } from "@cello-protocol/crypto";
import { sealParkEnvelope } from "../park-envelope.js";
import { decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import type { CelloNode } from "@cello-protocol/transport";
import { startTwoConnectionFixture, FakeNode, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { TEST_SESSION_GENESIS } from "./helpers/session-genesis.js";
import { wireContentHash } from "../wire-content-hash.js";
import { SESSION_CONTENT_ENCRYPTION_V1 } from "../content-encryption-status.js";
import { LEAF_KIND_MSG } from "../session-relay-client.js";
import { CONTENT_HASH_ALGS } from "../wire-content-hash.js";

const SID = "3c".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const BODY = new TextEncoder().encode("a line somebody has to be answerable for");
/** The key `createSession` agrees for content encryption — the fixture's completed key exchange. */
const CONTENT_KEY = new Uint8Array(32).fill(0x7e);
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Every frame the daemon actually wrote to the wire, decoded. Mirrors `send-names-its-algorithm`. */
function sentFrames(node: CelloNode | null): Array<Record<string, unknown>> {
  const raw = (node as unknown as { sent?: Uint8Array[] } | null)?.sent ?? [];
  return raw.flatMap((framed) => {
    for (let off = 0; off < Math.min(4, framed.length); off++) {
      try { return [decode(framed.subarray(off)) as Record<string, unknown>]; } catch { /* varint prefix */ }
    }
    return [];
  });
}

/**
 * An inbound content frame, built the way a real sender builds one.
 *
 * `fields` is spread LAST, so a test removes a field with an explicit `undefined` and adds a wrong
 * one by naming it — the frame shape is one place, and each test says only what it changes.
 */
function inboundFrame(fields: Record<string, unknown>): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "content_frame",
    // 034-CARRYLEAF: production names the leaf DOMAIN on every content frame, and a frame without
    // one is refused — witnessing under a guessed domain puts a wrong statement in the record.
    leaf_kind: 0x00,
    session_id: SID,
    content_hash: wireContentHash(BODY),
    content_bytes: sealSessionContent(CONTENT_KEY, BODY),
    content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
    ...fields,
  }) as Uint8Array).subarray();
}

/** The `structure1_cbor` the daemon actually put on the wire — read back, never reconstructed. */
function frameStructure1(node: CelloNode | null): Uint8Array {
  return sentFrames(node).find((f) => f["type"] === "content_frame")!["structure1_cbor"] as Uint8Array;
}

/** Structure 1 over THIS body, signed by `kp` — exactly what the send path now emits. */
async function signedClaim(
  kp: { getPublicKey(): Promise<Uint8Array>; sign(d: Uint8Array): Promise<Uint8Array> },
  opts: { contentHash?: Uint8Array } = {},
): Promise<{ structure1: Uint8Array; signature: Uint8Array; pubkeyHex: string }> {
  const senderPubkey = await kp.getPublicKey();
  /**
   * ⚠️ BOTH CHAIN LINKS ARE THE SESSION'S STARTING POINT, not two arbitrary fills —
   * `DOD-M15-SELFCHAIN-1`.
   *
   * They were `0xa7…` and `0xb4…`, from when nothing compared them. They are compared now. A first
   * message has received nothing and said nothing, and BOTH of those cases are the same defined
   * value: the starting point this fixture's session agreed. Leaving arbitrary bytes here made an
   * otherwise-perfect frame get refused for a broken chain, in tests written about a missing
   * signature — a refusal for the wrong reason reads as a pass to a test that only counts refusals.
   */
  const structure1 = encodeStructure1({
    contentHash: opts.contentHash ?? wireContentHash(BODY),
    senderPubkey,
    sessionId: Buffer.from(SID, "hex"),
    lastSeenSeq: 0,
    timestamp: 1_750_000_000_000,
    lastSeenHash: TEST_SESSION_GENESIS,
    prevOwnHash: TEST_SESSION_GENESIS,
  });
  return {
    structure1,
    signature: await kp.sign(structure1),
    pubkeyHex: Buffer.from(senderPubkey).toString("hex"),
  };
}

describe("DOD-M15-AUTHORSHIP-ABSENT-1 — a message with no passport does not get in", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ NO sender_signature: refused BY NAME, not ingested, and the operator is told", async () => {
    /**
     * The load-bearing test. Delete the absent-proof refusal and this goes red.
     *
     * The frame is otherwise perfect — right session, right hash, encrypted under the agreed key,
     * and it even carries `structure1_cbor`. The ONLY thing missing is the signature over it, which
     * is precisely the omission the old code read as "nothing to check here".
     */
    const kp = generateKeypair();
    const { structure1, pubkeyHex } = await signedClaim(kp);
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-absent-" });
    await fx.createSession(SID, "alice", pubkeyHex, PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({ structure1_cbor: structure1 }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(
      notice,
      `a refusal nobody hears is indistinguishable from the message never arriving.\n${JSON.stringify(fx.eventsNamed("session.content.refused"))}`,
    ).toBeDefined();
    expect(notice!.reason).toBe("authorship_proof_absent");
    /**
     * ⚠️ **PIN THE OPENING, NOT A SUBSTRING** — review F1. This assertion was `/upgrade/i` alone,
     * and it stayed green while the guidance shipped beginning `NaNcopy in the relay mailbox…`: a
     * dropped literal turned the `+` before the next string into a unary plus, and "tell them to
     * upgrade" survives at the tail of the wreckage. A substring match cannot see a sentence that
     * lost its head.
     */
    expect(notice!.guidance.startsWith("STOPPED ON PURPOSE."), `the notice must OPEN with its framing, not mid-word: ${JSON.stringify(notice!.guidance.slice(0, 80))}`).toBe(true);
    expect(notice!.guidance, "no value ever reaches an operator's screen as NaN").not.toMatch(/NaN/);
    expect(notice!.guidance, "the reader must be given a next step they can actually perform").toMatch(/upgrade/i);

    // NOT INGESTED. The transcript is the record this unit exists to keep provable.
    expect(
      fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received"),
      "an unattributable message must not enter the transcript as a delivered one",
    ).toHaveLength(0);
  }, 60_000);

  it("★ absence REFUSES the message; it does NOT freeze the session", async () => {
    /**
     * `#freezeOnIdentityFailure` is for a proof that FAILED — a positive identity fault. An absent
     * proof is a version skew until proven otherwise, and freezing on it would turn every
     * un-upgraded peer into an incident that only a new session can clear.
     *
     * ⚠️ **THIS TEST WAS HOLLOW AND THE REVIEWER MEASURED IT.** It asserted the no-freeze half
     * alone — which was ALREADY TRUE before this unit, because the frame was simply ingested. So it
     * was green on `origin/main`, failed the revert test, and its name promised two facts while it
     * held the one that needed no holding. Both halves are asserted now: the refusal is the fact
     * this unit adds, and the no-freeze is the fact it must not break.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-nofreeze-" });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({}), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice, "the message is REFUSED — this is the half that was not asserted").toBeDefined();
    expect(notice!.reason).toBe("authorship_proof_absent");
    expect(
      fx.eventsNamed("session.content.identity.frozen"),
      "a missing passport is not evidence about the counterparty's key",
    ).toHaveLength(0);
  }, 60_000);

  it("★ a sender_signature with NO structure1_cbor is refused, and the log says WHICH half is missing", async () => {
    /**
     * Review T3: the `hasStructure1` / `hasSenderSignature` fields were added so an investigator
     * would not have to guess which half a peer omitted, and nothing asserted either of them. A
     * sender on an older build supplies neither; a frame stripped in flight is likelier to be
     * missing one, and the two must be tellable apart.
     */
    const kp = generateKeypair();
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-halfproof-" });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      sender_signature: await kp.sign(new Uint8Array([1, 2, 3])),
    }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice!.reason).toBe("authorship_proof_absent");
    const logged = fx.eventsNamed("session.content.refused").at(-1)!;
    expect(logged.ctx["hasStructure1"], "there were no signed bytes to check the signature against").toBe(false);
    expect(logged.ctx["hasSenderSignature"], "and the signature itself did arrive — that is the distinction").toBe(true);
  }, 60_000);

  it("★ a signature that DOES NOT VERIFY still freezes — the existing FATAL verdict, unchanged", async () => {
    const kp = generateKeypair();
    const { structure1, pubkeyHex } = await signedClaim(kp);
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-badsig-" });
    await fx.createSession(SID, "alice", pubkeyHex, PEER);

    // 64 bytes of the right SHAPE and the wrong value — a proof supplied and refuted, which is a
    // different fact from a proof withheld.
    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      structure1_cbor: structure1,
      sender_signature: new Uint8Array(64).fill(0x11),
    }), PEER);

    const frozen = fx.eventsNamed("session.content.identity.frozen");
    expect(frozen, "a refuted proof is an identity fault and must still freeze").toHaveLength(1);
    expect(frozen[0]!.ctx["reason"]).toBe("bad_signature");
  }, 60_000);

  it("★ a VALID signature by someone who is not the counterparty still freezes", async () => {
    const stranger = generateKeypair();
    const { structure1, signature } = await signedClaim(stranger);
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-wrongsigner-" });
    // The session is with a DIFFERENT key, so the signer is provably not who this session is with.
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      structure1_cbor: structure1,
      sender_signature: signature,
    }), PEER);

    const frozen = fx.eventsNamed("session.content.identity.frozen");
    expect(frozen).toHaveLength(1);
    expect(frozen[0]!.ctx["reason"]).toBe("signer_not_counterparty");
  }, 60_000);

  it("★ an UNREADABLE structure1_cbor is refused — a claim we cannot read is not a claim", async () => {
    /**
     * ⚠️ **THIS TEST EXISTS BECAUSE THE MUTATION LOOP FOUND ITS ABSENCE.** Turning the verifier's
     * unreadable-layout branch into a soft `verified_unmatched` — the shape a peer speaking a
     * layout this build cannot name would take — left the whole suite green. Missing, malformed and
     * mismatched are supposed to share one path, and only two of the three were held.
     *
     * The bytes are valid CBOR and not a Structure 1 at all, so this is the SHAPE failure rather
     * than the decode failure: it reaches `decodeStructure1` and comes back named.
     */
    const kp = generateKeypair();
    const junk = encodeCbor([9, "not a structure 1"]) as Uint8Array;
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-junk-" });
    await fx.createSession(SID, "alice", Buffer.from(await kp.getPublicKey()).toString("hex"), PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      structure1_cbor: junk,
      // A real signature over the junk: the sender is not being careless, they are speaking a
      // layout we cannot read. It must not matter that the signature itself is well-formed.
      sender_signature: await kp.sign(junk),
    }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice, "a claim in a layout this build cannot name is not a proof of anything").toBeDefined();
    expect(notice!.reason).toBe("authorship_proof_unusable");
    expect(
      fx.eventsNamed("session.content.identity.frozen"),
      "and an unreadable layout is a version skew, not an accusation",
    ).toHaveLength(0);
    expect(fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received")).toHaveLength(0);
  }, 60_000);

  it("★ a claim signed for ANOTHER SESSION is refused — a real message, the wrong conversation", async () => {
    /**
     * ⚠️ **THE REPLAY THIS UNIT'S FIRST PASS LEFT OPEN** — review M4, ruled in by Andre 2026-09-04.
     *
     * The claim binds the CONTENT and the SIGNER and nothing else, so a claim your counterparty
     * genuinely signed in conversation X verifies unchanged in conversation Y for the same bytes.
     * Not a stranger, not forged content — a real line of theirs, appearing in a transcript it was
     * never written for, carrying a signature that checks out. That is worse than an unsigned
     * message, because the receipt then PROVES something that did not happen.
     *
     * The signed session id has been in Structure 1 since v1 and nothing on this path ever read it.
     * `seal-frontier-verify` already compares it — this side simply did not.
     */
    const kp = generateKeypair();
    const senderPubkey = await kp.getPublicKey();
    const OTHER_SESSION = "7b".repeat(32);
    // Everything is right except the conversation it was signed for.
    const structure1 = encodeStructure1({
      contentHash: wireContentHash(BODY),
      senderPubkey,
      sessionId: Buffer.from(OTHER_SESSION, "hex"),
      lastSeenSeq: 0,
      timestamp: 1_750_000_000_000,
      lastSeenHash: new Uint8Array(32).fill(0xa7),
      prevOwnHash: new Uint8Array(32).fill(0xb4),
    });
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-othersession-" });
    await fx.createSession(SID, "alice", Buffer.from(senderPubkey).toString("hex"), PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      structure1_cbor: structure1,
      sender_signature: await kp.sign(structure1),
    }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice, "a claim for another conversation is not a claim about this one").toBeDefined();
    expect(
      fx.eventsNamed("session.content.refused").at(-1)!.ctx["detail"],
      "and the forensic record names WHICH way it was unusable",
    ).toBe("session_mismatch");
    expect(
      fx.eventsNamed("session.content.identity.frozen"),
      "refused, not frozen: the signature verified — it is about a different conversation",
    ).toHaveLength(0);
    /**
     * THE OPERATOR SURFACE, asserted — review of `029b`. This refusal reached the inbox under the
     * generic `unusable` wording, which says the proof was "unreadable, or signed over different
     * content" (neither is true here) and tells the reader to ask their counterparty to upgrade. A
     * replayed signature is not a version problem, and sending someone to chase a version number
     * spends their attention on the wrong thing.
     */
    expect(notice!.reason, "its own name on the surface the operator reads, not only in the log").toBe("authorship_wrong_conversation");
    expect(notice!.impact, "the impact says a VALID signature of theirs arrived for another conversation").toMatch(/VALID signature .* DIFFERENT conversation/);
    expect(notice!.guidance, "and the guidance must NOT send them to chase a build number").not.toMatch(/upgrade/i);
    expect(notice!.guidance, "the one move that works is out of band").toMatch(/OUT OF BAND/);
    expect(fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received")).toHaveLength(0);
  }, 60_000);

  it("★★★ A WRONG SESSION ID CANNOT BUY A SOFTER OUTCOME — the freeze-suppression switch", async () => {
    /**
     * ⚠️ **THIS IS THE TEST THE REVIEW WAS RIGHT ABOUT, AND IT WAS RED WHEN IT WAS WRITTEN.**
     *
     * The session-binding check was placed BEFORE the signature verification. Everything below that
     * line refuses the message and lets the session live; everything above it freezes the session.
     * So a peer could pick the softer outcome: send a garbage signature — or a valid signature by a
     * MITM's own key — and ALSO flip one unauthenticated byte of `session_id` inside the claim. The
     * session-mismatch refusal answered first, the freeze never fired, and the session-open MITM
     * detection was switched off by the party it exists to detect, for free.
     *
     * Both halves are driven here, because they are two different attackers: one who cannot sign at
     * all, and one who signs perfectly with the wrong key. Neither may escape the freeze by lying
     * about which conversation they are in.
     */
    const stranger = generateKeypair();
    const OTHER = "7b".repeat(32);
    const claimFor = async (kp: { getPublicKey(): Promise<Uint8Array>; sign(d: Uint8Array): Promise<Uint8Array> }) => {
      const structure1 = encodeStructure1({
        contentHash: wireContentHash(BODY),
        senderPubkey: await kp.getPublicKey(),
        sessionId: Buffer.from(OTHER, "hex"),
        lastSeenSeq: 0,
        timestamp: 1_750_000_000_000,
        lastSeenHash: new Uint8Array(32).fill(0xa7),
        prevOwnHash: new Uint8Array(32).fill(0xb4),
      });
      return { structure1, signature: await kp.sign(structure1) };
    };

    // (a) an UNSIGNABLE attacker: right key in the claim, garbage signature, wrong session id.
    const counterparty = generateKeypair();
    const cpHex = Buffer.from(await counterparty.getPublicKey()).toString("hex");
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-suppress-a-" });
    await fx.createSession(SID, "alice", cpHex, PEER);
    const good = await claimFor(counterparty);
    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      structure1_cbor: good.structure1,
      sender_signature: new Uint8Array(64).fill(0x11),
    }), PEER);
    expect(
      fx.eventsNamed("session.content.identity.frozen"),
      "a signature that does not verify freezes, WHATEVER conversation the claim names",
    ).toHaveLength(1);
    expect(fx.eventsNamed("session.content.identity.frozen")[0]!.ctx["reason"]).toBe("bad_signature");
    await fx.cleanup();

    // (b) a MITM: a perfect signature by their OWN key, plus the wrong session id.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-suppress-b-" });
    await fx.createSession(SID, "alice", cpHex, PEER);
    const mitm = await claimFor(stranger);
    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      structure1_cbor: mitm.structure1,
      sender_signature: mitm.signature,
    }), PEER);
    expect(
      fx.eventsNamed("session.content.identity.frozen"),
      "and a signer who is not the counterparty freezes too — this is the session-open MITM detection",
    ).toHaveLength(1);
    expect(fx.eventsNamed("session.content.identity.frozen")[0]!.ctx["reason"]).toBe("signer_not_counterparty");
  }, 60_000);

  it("★ a signature over DIFFERENT content is refused — it proves nothing about THIS message", async () => {
    /**
     * The proof is present, verifies, and is by the right key — over somebody else's bytes. Reading
     * that as authorship for this message is the same hole with a longer path: it lets a sender
     * replay one signed claim over every frame after it.
     */
    const kp = generateKeypair();
    const other = await signedClaim(kp, { contentHash: wireContentHash(new TextEncoder().encode("a different line")) });
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-otherhash-" });
    await fx.createSession(SID, "alice", other.pubkeyHex, PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      structure1_cbor: other.structure1,
      sender_signature: other.signature,
    }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice, "a proof that does not describe this message is not a proof of it").toBeDefined();
    expect(notice!.reason).toBe("authorship_proof_unusable");
    expect(fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received")).toHaveLength(0);
  }, 60_000);
});

describe("DOD-M15-AUTHORSHIP-ABSENT-1 — the refusal does NOT hold, and the operator is told so", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ the refused message arrives via the relay mailbox, and the two events become one story", async () => {
    /**
     * ⚠️ **REVIEW H1 — THE REFUSAL ANNOUNCED MORE THAN IT DELIVERED.**
     *
     * Walked as the operator lives it: their counterparty is on an older build → the message is
     * refused on the direct path for carrying no proof of who wrote it → **no delivery ACK goes
     * back**, so the sender's backstop parks a sealed copy in the relay mailbox → this side pulls
     * it, the ENVELOPE's signature authenticates it, and it is delivered. The operator had just
     * been told "nothing was stored", and then watched the message appear.
     *
     * The park path is deliberately NOT changed — gating mail retrieval on a per-message record the
     * relay-degraded path may omit is the false positive this whole unit avoids, and the order
     * scopes the envelope out. What is fixed is the silence: the two events are one story now.
     */
    const sender = generateKeypair();
    const recipient = generateKeypair();
    const recipientPub = await recipient.getPublicKey();
    const contentHash = wireContentHash(BODY);

    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-reconcile-" });
    await fx.createSession(SID, "alice", Buffer.from(await sender.getPublicKey()).toString("hex"), PEER);

    // 1. The direct frame, with no proof. Refused by name.
    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({}), PEER);
    expect(fx.snm.takeContentRefusals("alice", SID, "op")[0]!.reason).toBe("authorship_proof_absent");

    // 2. The SAME content, arriving the other way — sealed to this recipient, exactly as the
    //    sender's park backstop deposits it.
    const sealed = await sealParkEnvelope({
      signer: sender, sessionIdHex: SID, recipientPubkey: recipientPub, content: BODY, contentHash,
    });
    const plaintext = await recipient.openContentSeal!(sealed);
    const recovered = await fx.snm.recoverParkedEntry("alice", SID, recipientPub, plaintext!, contentHash, "corr");

    expect(recovered.ok, "the mailbox copy is accepted on the envelope's signature — unchanged, and correct").toBe(true);
    const reconciled = fx.eventsNamed("content.recover.refusal_reconciled").at(-1);
    expect(
      reconciled,
      "without this line the operator reads REFUSED, watches the message arrive, and has nothing connecting the two",
    ).toBeDefined();
    expect(reconciled!.ctx["contentHash"]).toBe(Buffer.from(contentHash).toString("hex"));
    expect(
      String(reconciled!.ctx["impact"]),
      "and it must name what is ACTUALLY lost — the per-message proof, not the delivery",
    ).toMatch(/WAS delivered by the other route/);
  }, 60_000);

  it("★ a message that was never refused produces NO reconciliation line", async () => {
    /**
     * The other half, and the reason the memo is keyed on the content hash rather than the session:
     * a warning that fires on the benign steady state is not a signal. Every ordinary parked message
     * would otherwise carry an alarm about a refusal that never happened.
     */
    const sender = generateKeypair();
    const recipient = generateKeypair();
    const recipientPub = await recipient.getPublicKey();
    const contentHash = wireContentHash(BODY);

    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-noreconcile-" });
    await fx.createSession(SID, "alice", Buffer.from(await sender.getPublicKey()).toString("hex"), PEER);

    const sealed = await sealParkEnvelope({
      signer: sender, sessionIdHex: SID, recipientPubkey: recipientPub, content: BODY, contentHash,
    });
    const plaintext = await recipient.openContentSeal!(sealed);
    expect((await fx.snm.recoverParkedEntry("alice", SID, recipientPub, plaintext!, contentHash, "corr")).ok).toBe(true);

    expect(
      fx.eventsNamed("content.recover.refusal_reconciled"),
      "an ordinary parked message must not carry an alarm about a refusal that never happened",
    ).toHaveLength(0);
  }, 60_000);
});

describe("DOD-M15-AUTHORSHIP-ABSENT-1 — POSITION stays soft, which is the half a careless fix breaks", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a valid signature with NO structure2_cbor is ACCEPTED and ingested", async () => {
    /**
     * THE RELAY-DEGRADED PATH. This is what the original "both structures or neither" branch was
     * protecting, and making Structure 2 mandatory would silence an honest peer whose relay is
     * unreachable. The message lands; only its POSITION falls back to the witness stream.
     */
    const kp = generateKeypair();
    const { structure1, signature, pubkeyHex } = await signedClaim(kp);
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-nopos-" });
    await fx.createSession(SID, "alice", pubkeyHex, PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({
      structure1_cbor: structure1,
      sender_signature: signature,
    }), PEER);

    expect(
      fx.snm.takeContentRefusals("alice", SID, "op"),
      `a message with a good signature and no relay record must NOT be refused.\n${JSON.stringify(fx.eventsNamed("session.content.refused"))}`,
    ).toHaveLength(0);
    const delivered = fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received");
    expect(delivered, "it is delivered, exactly as before this unit").toHaveLength(1);
    expect(
      fx.eventsNamed("session.content.ordering.absent"),
      "and the event still fires — after this unit it is about POSITION, which is the only thing that can be absent",
    ).toHaveLength(1);
  }, 60_000);
});

describe("DOD-M15-AUTHORSHIP-ABSENT-1 — every outbound content frame carries its own proof", () => {
  let fx: TwoConnectionFixture | null = null;
  let node: CelloNode | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; node = null; });

  it("★ with NO relay in the session, the frame still carries structure1_cbor + sender_signature", async () => {
    /**
     * The whole defect on the send side: Structure 1 was built and signed INSIDE the relay submit,
     * so a session with no relay never built one and the frame went out with nothing to check.
     *
     * The fixture's non-relay `createSession` is exactly that session. The assertion verifies the
     * signature the way a counterparty does — against the key inside the signed bytes — rather than
     * checking that a field is merely present, which any 64 bytes would satisfy.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-send-", node: node = new FakeNode() as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);

    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    const res = await fx.snm.sendContent("alice", SID, BODY, hash, "corr", LEAF_KIND_MSG, alg);
    await wait(200);

    /**
     * Review M3 — OUR OWN ROW GETS THE PROOF TOO. `authorship` used to be set only when the relay
     * witnessed the leaf, so on this path the counterparty's transcript could prove we wrote the
     * message and ours could not: `self_authored`, signature NULL, indistinguishable from a send
     * nothing ever witnessed. The proof was produced three lines earlier and thrown away.
     */
    expect(res.ok).toBe(true);
    const authorship = res.authorship;
    expect(authorship, "a proof this side produced must reach this side's transcript row").toBeDefined();
    expect(
      verify(authorship!.senderPubkey, frameStructure1(node), authorship!.senderSig),
      "and it must verify against the key inside the bytes it signs — not merely be present",
    ).toBe(true);

    const frame = sentFrames(node).find((f) => f["type"] === "content_frame");
    expect(frame, "the send must reach the wire for this to prove anything").toBeDefined();
    const s1 = frame!["structure1_cbor"];
    const sig = frame!["sender_signature"];
    expect(s1, "no Structure 1 means the receiver has nothing to check").toBeInstanceOf(Uint8Array);
    expect(sig, "this is the field that never existed on a content frame").toBeInstanceOf(Uint8Array);

    // Verified the way the counterparty verifies it: the key comes from INSIDE the signed bytes.
    const decoded = decode(s1 as Uint8Array) as unknown[];
    const senderPubkey = decoded[2] as Uint8Array;
    expect(
      verify(senderPubkey, s1 as Uint8Array, sig as Uint8Array),
      "a signature that does not verify against the key in its own bytes is decoration",
    ).toBe(true);
    // And it binds THIS message, not some other one.
    expect(Buffer.from(decoded[1] as Uint8Array).toString("hex")).toBe(Buffer.from(hash).toString("hex"));
    expect(alg).toBe(CONTENT_HASH_ALGS.SHA256);

    // POSITION is not invented. Nothing witnessed this leaf, so no relay record rides with it.
    expect(
      frame!["structure2_cbor"],
      "structure2 travels only with the structure1 it was committed against",
    ).toBeUndefined();
  }, 60_000);

  it("★ the signature is by THIS agent's identity key, not an arbitrary one", async () => {
    /**
     * A frame signed by a freshly minted keypair would pass the test above and be refused by every
     * counterparty on earth: the signer would not be the agent they opened the session with.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-authorship-send-key-", node: node = new FakeNode() as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);

    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    await fx.snm.sendContent("alice", SID, BODY, hash, "corr", LEAF_KIND_MSG, alg);
    await wait(200);

    const frame = sentFrames(node).find((f) => f["type"] === "content_frame")!;
    const decoded = decode(frame["structure1_cbor"] as Uint8Array) as unknown[];
    const onWire = Buffer.from(decoded[2] as Uint8Array).toString("hex");
    /**
     * The identity read from the DAEMON'S OWN identity store — the row every registration, every
     * assignment and every counterparty's `counterparty_pubkey` is derived from. Comparing against
     * a key this test loaded itself would only prove the two agree about a file.
     */
    const { k_local_pubkey } = fx.snm.getDb()
      .prepare("SELECT k_local_pubkey FROM agents WHERE agent_name = ?")
      .get("alice") as { k_local_pubkey: string };
    expect(onWire, "the counterparty matches this against the key they opened the session with")
      .toBe(k_local_pubkey);
  }, 60_000);
});
