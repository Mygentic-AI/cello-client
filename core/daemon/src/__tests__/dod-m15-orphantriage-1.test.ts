/**
 * DOD-M15-ORPHANTRIAGE-1 — a message for a conversation we never had.
 *
 * ─── The failure, from the operator's chair ────────────────────────────────────────────────────
 *
 * A message arrives naming a conversation your machine has never held. We refuse it, correctly, and
 * then we tell you: *"ask the counterparty to start a NEW session."* If that message came from a
 * stranger who guessed your peer id, **that instruction is what they sent it for.** They learn
 * somebody is home and that your agent answers — from a message that was refused.
 *
 * Reaching out is warranted only when the message carries a signature that verifies, against a key
 * the operator has VOUCHED for, in a conversation this machine still holds part of. Everything else
 * gets the default, which is report.
 *
 * ─── What this file pins, and what it deliberately does not ────────────────────────────────────
 *
 * Here: the rendered prose for each signal set, that `ingestReceivedContent` derives the address-book
 * and transcript signals ITSELF rather than being handed them, and that a contact row which merely
 * EXISTS is not a vouch.
 *
 * Also here, since review T5: that the verified signature SURVIVES the session lookup, driven through
 * the real inbound content handler with a real Ed25519 signature over real `encodeStructure1` bytes.
 * The last describe block is that guard. Until it existed the unit's central mechanism was held by
 * the spine journey alone — the file most likely to be skipped, or waved off as already red.
 *
 * The spine journey remains the stronger evidence and is not replaced: it proves the same thing with
 * two operating-system processes and a real relay, where nothing in this file can. What no fixture
 * anywhere may do is assert "we were told it verified" — that proves nothing about the branch whose
 * job is to do the verifying.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { TIER } from "../contacts-tier-migration.js";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor, encodeStructure1 } from "@cello-protocol/protocol-types";
import { generateKeypair, sealSessionContent } from "@cello-protocol/crypto";
import { wireContentHash } from "../wire-content-hash.js";
import { SESSION_CONTENT_ENCRYPTION_V1 } from "../content-encryption-status.js";
import * as lp from "it-length-prefixed";
import type { Logger, DaemonConfig } from "../types.js";
import {
  triageOrphanedContent,
  ORPHAN_ACTIONS,
  NOT_CHECKED,
  WHEN_IN_DOUBT,
  MESSAGE_NOT_RETAINED,
  type OrphanEvidence,
} from "../orphan-triage.js";

/** The leaf hash the receiver recomputes: sha256(0x00 ‖ content). Mirrors `daemon-004-tree`. */
function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

/**
 * A key that is 64 hex characters and recognisable in a failure message.
 *
 * ⚠️ **DELIBERATELY NOT A REPEATED BYTE.** `"aa".repeat(32)` renders as a run of one character, so
 * an assertion that the FULL key appears cannot tell a complete key from a truncated one — every
 * prefix of it is also a substring of it. This one differs at both ends.
 */
const SIGNER_HEX = "9c1f4e77" + "b3".repeat(24) + "0d5a72e8";

/**
 * Every verb that would send the operator to whoever sent this, including the ones a PROHIBITION
 * would use. "Do not contact them" puts the verb on the page just as surely as an invitation does.
 *
 * ⚠️ **THIS LIST IS A BELT, NOT THE GATE** — review T1. A hand-maintained blocklist fails by
 * OMISSION: leaving a verb out makes the loop shorter, never red, and the first version of it had
 * been calibrated to the prose rather than to the rule (it missed `answer` and `respond`, both of
 * which the prose then used). The gate is the exact-equality pin below, which reddens on ANY edit
 * to the guidance and forces a human to re-read it.
 */
const CONTACT_VERBS = [
  /\bcontact\b/i, /reach out/i, /\breply\b/i, /\bget back to\b/i, /get in touch/i,
  /cello_initiate_session/, /\bnew conversation\b/i, /\bnew session\b/i, /\bmessage them\b/i,
  /\bask them\b/i, /\btell them\b/i, /\bnotify\b/i, /\bresend\b/i, /\banswer\b/i, /\brespond\b/i,
  /\bping them\b/i, /\bwrite to them\b/i, /\blet them know\b/i,
];

/** Wordings that claim an identity a signature cannot establish. */
const IDENTITY_CLAIMS = [/message (is|was|came) from/i, /\bsent by\b/i, /\bthis is from\b/i];

/**
 * The report-only guidance, WRITTEN OUT — review T1's remedy, and the reason it is written out
 * rather than imported is the whole point: importing the constant would assert the module equals
 * itself. Any edit to that prose reddens this, and the person making the edit has to re-read the
 * verb rule before they can go green again.
 */
const REPORT_ONLY_UNSIGNED =
  "ONE thing to do: record it as a report. Nothing goes back, nothing is opened, and this one is left exactly where it stands — silence is the correct move here. " +
  "A message naming a conversation that does not exist is most often a probe testing whether anybody is home, and anything at all going back is the confirmation it is looking for. " +
  "CELLO has no agent to receive reports yet, so there is no command here that would send one. " +
  "Write down the conversation id above, the time you are reading this, and the fact that the message carried no signature anyone could check — that IS the report — and keep it until there is somewhere to send it. " +
  `${MESSAGE_NOT_RETAINED} ${WHEN_IN_DOUBT}`;

const REPORT_ONLY_SIGNED =
  "ONE thing to do: record it as a report. Nothing goes back, nothing is opened, and this one is left exactly where it stands — silence is the correct move here. " +
  "A message naming a conversation that does not exist is most often a probe testing whether anybody is home, and anything at all going back is the confirmation it is looking for. " +
  "CELLO has no agent to receive reports yet, so there is no command here that would send one. " +
  `Write down the public key above, the conversation id, and the time you are reading this — that IS the report — and keep it until there is somewhere to send it. ` +
  `${MESSAGE_NOT_RETAINED} ${WHEN_IN_DOUBT}`;

const KNOWN_AND_ONGOING: OrphanEvidence = {
  signerPubkeyHex: SIGNER_HEX, knownContact: true, contactMoniker: "Bob", ongoingConversation: true,
};

describe("DOD-M15-ORPHANTRIAGE-1 — the triage prose", () => {
  it("UNSIGNED — one action, report, and not one contact verb anywhere in the notice", () => {
    const t = triageOrphanedContent({
      signerPubkeyHex: null, knownContact: NOT_CHECKED, contactMoniker: null, ongoingConversation: NOT_CHECKED,
    });
    expect(t.action).toBe(ORPHAN_ACTIONS.REPORT);
    expect(t.guidance, "the guidance is pinned WORD FOR WORD — a blocklist fails by omission").toBe(REPORT_ONLY_UNSIGNED);
    for (const verb of CONTACT_VERBS) {
      expect(`${t.impact} ${t.guidance}`, `an unsigned message must name no way to answer it; matched ${String(verb)}`).not.toMatch(verb);
    }
    // "Not signed" is a FINDING. An operator who reads it as a missing field goes looking for
    // information that does not exist.
    expect(t.impact, "the absence of a signature is stated as a finding, not as a gap")
      .toMatch(/nothing at all is known about who sent it — that is a finding, not a gap/);
    // Review F4: the only key-shaped thing here is the one the message CLAIMED, and the impact has
    // just said that claim proves nothing. Asking the operator to file it as evidence undoes that.
    expect(t.guidance, "and it must not ask them to write down a key it just called meaningless")
      .not.toMatch(/public key/);
  });

  it("A STRANGER WHO CAN SIGN IS STILL A STRANGER — same one action, and the key verbatim", () => {
    const t = triageOrphanedContent({
      signerPubkeyHex: SIGNER_HEX,
      knownContact: false,
      contactMoniker: null,
      ongoingConversation: true, // even here: an unvouched key is an unvouched key
    });
    expect(t.action).toBe(ORPHAN_ACTIONS.REPORT);
    expect(t.guidance).toBe(REPORT_ONLY_SIGNED);
    for (const verb of CONTACT_VERBS) {
      expect(`${t.impact} ${t.guidance}`, `an unvouched key must name no way to answer it; matched ${String(verb)}`).not.toMatch(verb);
    }
    expect(t.impact, "the operator may need to paste, compare or report this — never truncated").toContain(SIGNER_HEX);
    expect(`${t.impact} ${t.guidance}`, "and never abbreviated").not.toMatch(/…|\.\.\./);
    expect(t.impact, "a verified signature proves possession of a key and nothing more")
      .toMatch(/proves only that whoever produced it holds the private key matching that public key/);
    // The three ways to be unvouched are named rather than left as a silence — an operator who
    // recognises the key otherwise has no way to understand the advice, and ignores it.
    expect(t.impact, "and WHY they count as a stranger is said out loud")
      .toMatch(/absent from your address book, or present only because somebody dialled you, or blocked/);
  });

  it("A VOUCHED KEY WITH NO LOCAL TRACE STILL GETS REPORT — the conjunction is Andre's, not a nicety", () => {
    /**
     * The rule is *"if they are a known contact AND this was an ongoing conversation until this
     * point"*. Branching on the vouch alone produced a notice that argued with itself: an impact
     * saying nothing here favours a fault over a probe, above a guidance saying make contact anyway.
     */
    const t = triageOrphanedContent({ ...KNOWN_AND_ONGOING, ongoingConversation: false });
    expect(t.action).toBe(ORPHAN_ACTIONS.REPORT);
    expect(t.guidance).toBe(REPORT_ONLY_SIGNED);
    expect(t.impact, "and it says which half failed").toMatch(/holds no part of any conversation under the id the message names/);
  });

  it("A SIGNAL NOBODY MEASURED NEVER UNLOCKS CONTACT — not_checked is not a quiet false", () => {
    const t = triageOrphanedContent({
      signerPubkeyHex: SIGNER_HEX, knownContact: NOT_CHECKED, contactMoniker: null, ongoingConversation: NOT_CHECKED,
    });
    expect(t.action).toBe(ORPHAN_ACTIONS.REPORT);
    expect(t.impact, "and the operator is told it was not checked rather than told it was false")
      .toMatch(/could NOT be read on this machine/);
    expect(t.impact, "with the log event that says why").toMatch(/session\.content\.orphaned\.evidence\.failed/);
  });

  it("VOUCHED KEY + LOCAL TRACE — reaching out is offered, explicitly in a NEW conversation", () => {
    const t = triageOrphanedContent(KNOWN_AND_ONGOING);
    expect(t.action).toBe(ORPHAN_ACTIONS.REACH_OUT_NEW_CONVERSATION);
    expect(t.guidance, "a NEW one — the conversation this message names must never be opened")
      .toMatch(/open a NEW conversation with/);
    expect(t.guidance, "and the reason the named one is off limits is stated, not assumed")
      .toMatch(/does not exist on this machine/);
    // The whole value of reaching out is the bad answer, and it is the half most likely to be cut.
    expect(t.guidance, "the key-compromise outcome is named")
      .toMatch(/is being used by someone else, and they can pause or burn that agent identity/);
    // Review F5: a CELLO conversation is authenticated by the key itself, so in the stolen-key case
    // — the exact case this reach-out exists to detect — the thief is the one who answers.
    expect(t.guidance, "and the remedy must admit that CELLO cannot answer its own question")
      .toMatch(/comes from whoever holds that key, so a "yes, that was me" proves nothing new/);
    expect(t.guidance, "naming the channel that can").toMatch(/out of band/);
    expect(t.impact, "possession, never identity").toMatch(/does NOT prove they are "Bob"/);
    expect(t.impact, "and the public key is what the operator knows, not the private one")
      .toMatch(/holds the private key matching the public key you know as "Bob"/);
    expect(t.impact).toContain(SIGNER_HEX);
    expect(t.impact, "the trace raises the odds of a fault — raises, never proves").toMatch(/likelier, not proven/);
    expect(t.guidance, "the sentence that catches an unsure operator is needed MOST here").toContain(WHEN_IN_DOUBT);
  });

  it("NO CASE CLAIMS THE MESSAGE IS *FROM* ANYONE, and every case says when in doubt", () => {
    /**
     * The one sentence that survives "and what if the key was stolen?" is "signed by the key you
     * know as X". "From X" does not, and it is the sentence an operator acts on hardest.
     */
    const cases: OrphanEvidence[] = [
      { signerPubkeyHex: null, knownContact: NOT_CHECKED, contactMoniker: null, ongoingConversation: NOT_CHECKED },
      { signerPubkeyHex: SIGNER_HEX, knownContact: false, contactMoniker: null, ongoingConversation: false },
      { signerPubkeyHex: SIGNER_HEX, knownContact: true, contactMoniker: null, ongoingConversation: false },
      KNOWN_AND_ONGOING,
      { ...KNOWN_AND_ONGOING, contactMoniker: null },
    ];
    for (const c of cases) {
      const t = triageOrphanedContent(c);
      const notice = `${t.impact} ${t.guidance}`;
      for (const claim of IDENTITY_CLAIMS) {
        expect(notice, `a signature identifies nobody; matched ${String(claim)}`).not.toMatch(claim);
      }
      expect(t.guidance, "every case, including the reach-out one").toContain(WHEN_IN_DOUBT);
      expect(t.guidance, "reporting is named as not yet reachable rather than as a verb that works")
        .toMatch(/CELLO has no agent to receive reports yet/);
      expect(t.guidance, "and the operator is told there is no artifact behind the report")
        .toContain(MESSAGE_NOT_RETAINED);
      expect(t.guidance, "the advice that made the probe succeed is gone")
        .not.toMatch(/ask the counterparty to start a NEW session/i);
      expect(t.impact, "and a repeated notice must not imply every arrival looked like the newest")
        .toMatch(/what follows describes the most recent one/);
    }
  });
});

describe("DOD-M15-ORPHANTRIAGE-1 — the orphan branch derives its own signals", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let logger: Logger;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-orphantriage-"));
    logger = { debug() {}, info() {}, warn() {}, error() {} };
    handle = null;
  });

  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function config(): Promise<DaemonConfig> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
  }

  /** A received transcript row for a session with no `sessions` row — a conversation that WAS working. */
  function seedTranscript(sessionId: string): void {
    const db = handle!.getSessionNodeManager().getDb()!;
    const row = db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get("alice") as { agent_id: string } | undefined;
    if (!row) throw new Error("test fixture bug: agent 'alice' has no 'agents' row yet");
    db.prepare(
      `INSERT INTO transcript (agent_id, session_id, sequence, direction, blob, created_at)
       VALUES (?, ?, 0, 'received', ?, ?)`,
    ).run(row.agent_id, sessionId, Buffer.from("earlier, when this worked"), Date.now());
  }

  async function refuse(sessionId: string, signer?: Uint8Array): Promise<{ impact: string; guidance: string }> {
    const mgr = handle!.getSessionNodeManager();
    const content = new TextEncoder().encode(`for ${sessionId}`);
    const res = await mgr.ingestReceivedContent(
      "alice", sessionId, content, msgLeafHash(content), undefined, undefined, undefined, undefined, signer,
    );
    expect((res as { reason: string }).reason).toBe("session_orphaned");
    const [notice] = mgr.takeContentRefusals("alice", sessionId, "op");
    expect(notice, "a session this daemon does not hold is the refusal with no other trace").toBeDefined();
    return { impact: notice!.impact, guidance: notice!.guidance };
  }

  it("NO SIGNER — report only, and the old advice that helped the prober is gone", async () => {
    handle = await startDaemon(await config());
    const n = await refuse("s-unsigned");
    expect(n.guidance).toBe(REPORT_ONLY_UNSIGNED);
    expect(n.guidance).not.toMatch(/ask the counterparty to start a NEW session/i);
    expect(n.guidance).toContain(WHEN_IN_DOUBT);
    // 022's notice said the sender keeps redelivering. That is still true and still said.
    expect(n.impact).toMatch(/redeliver/);
  });

  it("A VERIFIED SIGNER THE ADDRESS BOOK DOES NOT HOLD — still report only", async () => {
    handle = await startDaemon(await config());
    const n = await refuse("s-stranger", Buffer.from(SIGNER_HEX, "hex"));
    expect(n.impact, "the key is named in full so it can be pasted, compared and reported").toContain(SIGNER_HEX);
    expect(n.guidance).toBe(REPORT_ONLY_SIGNED);
  });

  it("A MERE CONTACT ROW IS NOT A VOUCH — an UNKNOWN-tier row still gets report only", async () => {
    /**
     * ⚠️ **THIS IS THE ONE THAT WAS SHIPPED WRONG, and it inverts the unit when it is.**
     *
     * `contacts` rows are written FROM THE WIRE with no operator action: `inbound-sessions.ts` calls
     * `addContact(..., "signal_presentation")` at `TIER.UNKNOWN` for any inbound offer inside the
     * acceptance bound, because the trust-signal foreign key needs a row to point at. A stranger who
     * merely dials therefore HAS a row — and a predicate that reads "does a row exist" hands them the
     * reach-out branch, which is the exact population this unit exists to refuse.
     *
     * `DOD-TIER-4` had already settled this and retired `isContact` for it: *"An UNKNOWN-tier contact
     * (a mere row) is NOT known."*
     */
    handle = await startDaemon(await config());
    const mgr = handle.getSessionNodeManager();
    mgr.addContact("alice", SIGNER_HEX, null, "signal_presentation", TIER.UNKNOWN);
    seedTranscript("s-dialled");
    const n = await refuse("s-dialled", Buffer.from(SIGNER_HEX, "hex"));
    expect(n.guidance, "a row somebody else caused is not a relationship the operator chose").toBe(REPORT_ONLY_SIGNED);
    expect(n.impact).toMatch(/present only because somebody dialled you, or blocked/);
  });

  it("A BLOCKED KEY GETS REPORT ONLY — blocking leaves the row behind, and the row must not speak for it", async () => {
    /**
     * Blocking is an UPDATE to `TIER.BLOCKED`, not a delete. A row-existence predicate would tell an
     * operator who deliberately blocked a key to go and open a conversation with it.
     */
    handle = await startDaemon(await config());
    const mgr = handle.getSessionNodeManager();
    mgr.addContact("alice", SIGNER_HEX, "Bob", null, TIER.BLOCKED);
    seedTranscript("s-blocked");
    const n = await refuse("s-blocked", Buffer.from(SIGNER_HEX, "hex"));
    expect(n.guidance, "the operator already answered this question, in the other direction").toBe(REPORT_ONLY_SIGNED);
  });

  it("A VOUCHED KEY WITH NO LOCAL TRACE — report only, because the conjunction is not satisfied", async () => {
    handle = await startDaemon(await config());
    handle.getSessionNodeManager().addContact("alice", SIGNER_HEX, "Bob", null, TIER.KNOWN);
    // No seedTranscript: this machine holds nothing under that id.
    const n = await refuse("s-notrace", Buffer.from(SIGNER_HEX, "hex"));
    expect(n.guidance).toBe(REPORT_ONLY_SIGNED);
    expect(n.impact).toMatch(/holds no part of any conversation under the id the message names/);
  });

  it("THE SAME SIGNER, ONCE VOUCHED AND WITH A LOCAL TRACE — the branch flips, and the DAEMON looks both up", async () => {
    /**
     * Nothing about the message changes between this test and the ones above. The only differences
     * are a tier in the operator's own address book and a row in their own transcript — neither of
     * which the sender can cause from the wire.
     */
    handle = await startDaemon(await config());
    handle.getSessionNodeManager().addContact("alice", SIGNER_HEX, "Bob", null, TIER.KNOWN);
    seedTranscript("s-known");
    const n = await refuse("s-known", Buffer.from(SIGNER_HEX, "hex"));
    expect(n.guidance, "reaching out is offered — in a NEW conversation").toMatch(/open a NEW conversation with/);
    expect(n.impact, "and the operator's own name for the key is used").toMatch(/"Bob"/);
    expect(n.impact, "possession, never identity").toMatch(/does NOT prove they are "Bob"/);
    expect(n.impact, "the local trace is read from OUR transcript, not from the sender's claim")
      .toMatch(/still holds part of a conversation under that id/);
    expect(n.guidance, "and the remedy admits CELLO cannot answer its own question").toMatch(/out of band/);
    expect(n.guidance).toContain(WHEN_IN_DOUBT);
  });

  it("A VOUCHED KEY WITH A MIXED-CASE CONTACT ROW IS STILL VOUCHED — hex case must not silently strand it", async () => {
    /**
     * `contacts.pubkey` is stored verbatim from the IPC parameter and is never case-normalized, so a
     * case-sensitive lookup would report a contact the operator can SEE in `cello_contacts` as an
     * unknown stranger. The failure direction is safe (report) and the notice would still be wrong.
     */
    handle = await startDaemon(await config());
    handle.getSessionNodeManager().addContact("alice", SIGNER_HEX.toUpperCase(), "Bob", null, TIER.KNOWN);
    seedTranscript("s-mixedcase");
    const n = await refuse("s-mixedcase", Buffer.from(SIGNER_HEX, "hex"));
    expect(n.guidance, "the address book holds this key; case is not a difference in identity")
      .toMatch(/open a NEW conversation with/);
  });
});

/**
 * ─── The mechanism, guarded a SECOND time and in-process — review T5 ───────────────────────────
 *
 * The unit's whole subject is a proof the daemon was computing and throwing away: the sender's
 * signature is verified against the key inside their own signed bytes, and then discarded because
 * the counterparty cross-check has no session record to compare it to. Until now the only guard on
 * that line was the spine journey — the file most likely to be skipped, or dismissed as already red.
 *
 * This drives the REAL inbound content handler with a REAL Ed25519 signature over REAL
 * `encodeStructure1` bytes, on a session whose row has been deleted underneath it. Nothing tells the
 * daemon the signature verified; it has to do that itself, and the key it names in the notice is the
 * proof it did.
 */
describe("DOD-M15-ORPHANTRIAGE-1 — the verified signer survives the session lookup, in-process", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  const SID = "ef".repeat(32);
  const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
  const BODY = new TextEncoder().encode("for a conversation you do not have");
  /** The key the fixture's `createSession` agrees for content encryption. */
  const CONTENT_KEY = new Uint8Array(32).fill(0x7e);

  /** A content frame carrying a genuinely signed ordering record, exactly as a real sender emits. */
  async function signedFrame(): Promise<{ framed: Uint8Array; signerHex: string }> {
    const kp = generateKeypair();
    const senderPubkey = await kp.getPublicKey();
    const contentHash = wireContentHash(BODY);
    const s1 = encodeStructure1({
      contentHash,
      senderPubkey,
      sessionId: Buffer.from(SID, "hex").subarray(0, 16),
      lastSeenSeq: 0,
      timestamp: 1_750_000_000_000,
    });
    // The signature the receiver verifies — over the EXACT bytes, by the key inside them.
    const sig = await kp.sign(s1);
    const s2 = encodeCbor([1, senderPubkey, contentHash, sig, null, null]) as Uint8Array;
    const framed = lp.encode.single(encodeCbor({
      type: "content_frame",
      session_id: SID,
      content_hash: contentHash,
      content_bytes: sealSessionContent(CONTENT_KEY, BODY),
      content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
      structure1_cbor: s1,
      structure2_cbor: s2,
    }) as Uint8Array).subarray();
    return { framed, signerHex: Buffer.from(senderPubkey).toString("hex") };
  }

  /** Remove the row the way production loses it: underneath a session node that is still live. */
  function dropSessionRow(agent: string): void {
    const db = fx!.snm.getDb();
    const { agent_id } = db.prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get(agent) as { agent_id: string };
    db.prepare("DELETE FROM sessions WHERE agent_id = ? AND session_id = ?").run(agent_id, SID);
  }

  it("★ a REAL signature on a rowless session reaches the notice — nothing hands the daemon the answer", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-orphan-wire-" });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);
    const { framed, signerHex } = await signedFrame();
    dropSessionRow("alice");

    await fx.snm.handleContentFrameForTest("alice", SID, framed, PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice, `the orphan branch must file a notice.\n${JSON.stringify(fx.eventsNamed("session.content.orphaned"))}`).toBeDefined();
    expect(notice!.reason).toBe("session_orphaned");
    expect(
      notice!.impact,
      "the daemon verified this signature itself and must say WHICH key it verified against — this is " +
      "the whole unit, and the only other guard on it is the spine",
    ).toContain(signerHex);
    // Unvouched, so the action is still report — the point is that the KEY survived, not the branch.
    expect(notice!.guidance).toBe(REPORT_ONLY_SIGNED);

    const logged = fx.eventsNamed("session.content.orphaned").at(-1)!;
    expect(logged.ctx!["signatureVerified"], "and the forensic record says the signature was checked").toBe(true);
    expect(logged.ctx!["signerPubkey"]).toBe(signerHex);
  }, 60_000);

  it("★ AN UNREADABLE ADDRESS BOOK IS RECORDED AS UNREAD, never as a measured 'no'", async () => {
    /**
     * ⚠️ **THIS TEST EXISTS BECAUSE ITS MUTANT SURVIVED.** The `"not_checked"` state was added for
     * review F6 — the log used to publish `knownContact: false` on paths that never looked — and the
     * mutation loop then turned it straight back into `false` with the whole suite still green.
     * Nothing exercised the manager's failure path, so the fix was prose with no consumer.
     *
     * The fault is injected the only way it happens for real: the read throws. An investigator
     * filtering `session.content.orphaned` days later is the ONLY person who will ever ask whether
     * that `false` was a reading, and a default wearing the shape of one is the cheapest possible
     * way to mislead them.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-orphan-wire-c-" });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);
    const { framed, signerHex } = await signedFrame();
    dropSessionRow("alice");
    // The address book becomes unreadable. Not a stub: the real SELECT throws, the real catch runs.
    fx.snm.getDb().prepare("DROP TABLE contacts").run();

    await fx.snm.handleContentFrameForTest("alice", SID, framed, PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice!.guidance, "and it still routes to the safe action").toBe(REPORT_ONLY_SIGNED);
    expect(notice!.impact, "the operator is told it could not be checked, not told the answer was no")
      .toMatch(/could NOT be read on this machine/);
    expect(notice!.impact).toContain(signerHex);

    const logged = fx.eventsNamed("session.content.orphaned").at(-1)!;
    expect(logged.ctx!["knownContact"], "the forensic record must not publish a reading nobody took").toBe(NOT_CHECKED);
    expect(logged.ctx!["ongoingConversation"]).toBe(NOT_CHECKED);
    expect(
      fx.eventsNamed("session.content.orphaned.evidence.failed").length,
      "and the reason it could not be read is on the record — this is the half that was silent",
    ).toBeGreaterThan(0);
  }, 60_000);

  it("★ the same frame with its ordering record REMOVED yields no key at all", async () => {
    /**
     * The other half of the same measurement. Identical bytes, identical session, one field gone —
     * so a green above cannot be coming from anywhere except the verification.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-orphan-wire-b-" });
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);
    const bare = lp.encode.single(encodeCbor({
      type: "content_frame",
      session_id: SID,
      content_hash: wireContentHash(BODY),
      content_bytes: sealSessionContent(CONTENT_KEY, BODY),
      content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
    }) as Uint8Array).subarray();
    dropSessionRow("alice");

    await fx.snm.handleContentFrameForTest("alice", SID, bare, PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(notice!.guidance).toBe(REPORT_ONLY_UNSIGNED);
    expect(fx.eventsNamed("session.content.orphaned").at(-1)!.ctx!["signatureVerified"]).toBe(false);
  }, 60_000);
});
