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
 * There are exactly two things ever worth doing, and which one applies is decided by evidence the
 * daemon already held and threw away: whether the message carries a signature that verifies, and
 * whether the key it verifies against is one the operator already knows.
 *
 * ─── What this file pins, and what it deliberately does not ────────────────────────────────────
 *
 * Here: the rendered prose for each of the three signal sets, and that `ingestReceivedContent`
 * derives the address-book and transcript signals ITSELF rather than being handed them.
 *
 * NOT here: that the signature verification survives the session lookup at all. That is proven over
 * the wire, with real keys and the real verifier, by `J-CONTENT`'s 024 journey — a fixture asserting
 * "we were told it verified" would prove nothing about the branch that has to do the verifying.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";
import {
  triageOrphanedContent,
  ORPHAN_ACTIONS,
  WHEN_IN_DOUBT,
  REPORTING_NOT_YET_AVAILABLE,
  MESSAGE_NOT_RETAINED,
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
 * Every verb that would send the operator to the sender, including the ones a prohibition would
 * use. The unsigned and unknown-key notices must contain NONE of them — a menu is how the wrong
 * option gets picked, and "do not contact them" puts the verb on the page just as surely as an
 * invitation does.
 */
const CONTACT_VERBS = [
  /\bcontact\b/i,
  /reach out/i,
  /\breply\b/i,
  /get in touch/i,
  /cello_initiate_session/,
  /\bnew conversation\b/i,
  /\bnew session\b/i,
  /\bmessage them\b/i,
  /\bask them\b/i,
  /\btell them\b/i,
  /\bresend\b/i,
];

/** Wordings that claim an identity a signature cannot establish. */
const IDENTITY_CLAIMS = [/message (is|was|came) from/i, /\bsent by\b/i, /\bthis is from\b/i];

describe("DOD-M15-ORPHANTRIAGE-1 — the triage prose", () => {
  it("UNSIGNED — one action, report, and not one contact verb anywhere in the notice", () => {
    const t = triageOrphanedContent({
      signerPubkeyHex: null,
      knownContact: false,
      contactMoniker: null,
      ongoingConversation: false,
    });
    expect(t.action).toBe(ORPHAN_ACTIONS.REPORT);
    const notice = `${t.impact} ${t.guidance}`;
    for (const verb of CONTACT_VERBS) {
      expect(notice, `an unsigned message must name no way to answer it; matched ${String(verb)}`).not.toMatch(verb);
    }
    // "Not signed" is a FINDING. An operator who reads it as a missing field goes looking for
    // information that does not exist.
    expect(t.impact, "the absence of a signature is stated as a finding, not as a gap")
      .toMatch(/nothing at all is known about who sent it — that is a finding, not a gap/);
    expect(t.guidance).toContain(WHEN_IN_DOUBT);
  });

  it("A STRANGER WHO CAN SIGN IS STILL A STRANGER — same one action, and the key verbatim", () => {
    const t = triageOrphanedContent({
      signerPubkeyHex: SIGNER_HEX,
      knownContact: false,
      contactMoniker: null,
      ongoingConversation: true, // even here: an unknown key is an unknown key
    });
    expect(t.action).toBe(ORPHAN_ACTIONS.REPORT);
    const notice = `${t.impact} ${t.guidance}`;
    for (const verb of CONTACT_VERBS) {
      expect(notice, `an unknown key must name no way to answer it; matched ${String(verb)}`).not.toMatch(verb);
    }
    expect(t.impact, "the operator may need to paste, compare or report this — never truncated").toContain(SIGNER_HEX);
    expect(notice, "and never abbreviated").not.toMatch(/…|\.\.\./);
    expect(t.impact, "a verified signature proves possession of a key and nothing more")
      .toMatch(/proves only that whoever produced it holds the private key/);
    expect(t.guidance).toContain(WHEN_IN_DOUBT);
  });

  it("KNOWN KEY + VERIFIED SIGNATURE — reaching out is offered, explicitly in a NEW conversation", () => {
    const t = triageOrphanedContent({
      signerPubkeyHex: SIGNER_HEX,
      knownContact: true,
      contactMoniker: "Bob",
      ongoingConversation: true,
    });
    expect(t.action).toBe(ORPHAN_ACTIONS.REACH_OUT_NEW_CONVERSATION);
    expect(t.guidance, "a NEW one — the conversation this message names must never be opened")
      .toMatch(/open a NEW conversation with/);
    expect(t.guidance, "and the reason the named one is off limits is stated, not assumed")
      .toMatch(/does not exist on this machine/);
    // The whole value of reaching out is the bad answer, and it is the half most likely to be cut.
    expect(t.guidance, "the key-compromise outcome is named")
      .toMatch(/is being used by someone else, and they can pause or burn that agent identity/);
    expect(t.impact, "possession, never identity").toMatch(/does NOT prove they are "Bob"/);
    expect(t.impact).toContain(SIGNER_HEX);
    expect(t.guidance, "the sentence that catches an unsure operator is needed MOST here").toContain(WHEN_IN_DOUBT);
  });

  it("NO CASE CLAIMS THE MESSAGE IS *FROM* ANYONE, and every case says when in doubt", () => {
    /**
     * The one sentence that survives "and what if the key was stolen?" is "signed by the key you
     * know as X". "From X" does not, and it is the sentence an operator acts on hardest.
     */
    const cases = [
      { signerPubkeyHex: null, knownContact: false, contactMoniker: null, ongoingConversation: false },
      { signerPubkeyHex: SIGNER_HEX, knownContact: false, contactMoniker: null, ongoingConversation: false },
      { signerPubkeyHex: SIGNER_HEX, knownContact: true, contactMoniker: "Bob", ongoingConversation: true },
      { signerPubkeyHex: SIGNER_HEX, knownContact: true, contactMoniker: null, ongoingConversation: false },
    ];
    for (const c of cases) {
      const t = triageOrphanedContent(c);
      const notice = `${t.impact} ${t.guidance}`;
      for (const claim of IDENTITY_CLAIMS) {
        expect(notice, `a signature identifies nobody; matched ${String(claim)}`).not.toMatch(claim);
      }
      expect(t.guidance, "every case, including the reach-out one").toContain(WHEN_IN_DOUBT);
      expect(t.guidance, "reporting is named as not yet reachable rather than as a verb that works")
        .toContain(REPORTING_NOT_YET_AVAILABLE);
      expect(t.guidance, "and the operator is told there is no artifact behind the report")
        .toContain(MESSAGE_NOT_RETAINED);
      expect(t.guidance, "the advice that made the probe succeed is gone")
        .not.toMatch(/ask the counterparty to start a NEW session/i);
    }
  });

  it("A KNOWN KEY WITH NO LOCAL TRACE OF THE CONVERSATION SAYS SO — the signal is not silently dropped", () => {
    const withTrace = triageOrphanedContent({ signerPubkeyHex: SIGNER_HEX, knownContact: true, contactMoniker: "Bob", ongoingConversation: true });
    const without = triageOrphanedContent({ signerPubkeyHex: SIGNER_HEX, knownContact: true, contactMoniker: "Bob", ongoingConversation: false });
    expect(withTrace.impact, "a partial local record raises the odds of a fault — raises, never proves")
      .toMatch(/likelier, not proven/);
    expect(without.impact, "and its absence is stated rather than left blank")
      .toMatch(/nothing here that makes a technical fault more likely than a probe/);
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
    const mgr = handle!.getSessionNodeManager();
    const db = mgr.getDb()!;
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
    for (const verb of CONTACT_VERBS) {
      expect(`${n.impact} ${n.guidance}`, `matched ${String(verb)}`).not.toMatch(verb);
    }
    expect(n.guidance).not.toMatch(/ask the counterparty to start a NEW session/i);
    expect(n.guidance).toContain(WHEN_IN_DOUBT);
    // 022's notice said the sender keeps redelivering. That is still true and still said.
    expect(n.impact).toMatch(/redeliver/);
  });

  it("A VERIFIED SIGNER THE ADDRESS BOOK DOES NOT HOLD — still report only", async () => {
    handle = await startDaemon(await config());
    const n = await refuse("s-stranger", Buffer.from(SIGNER_HEX, "hex"));
    expect(n.impact, "the key is named in full so it can be pasted, compared and reported").toContain(SIGNER_HEX);
    for (const verb of CONTACT_VERBS) {
      expect(`${n.impact} ${n.guidance}`, `matched ${String(verb)}`).not.toMatch(verb);
    }
  });

  it("THE SAME SIGNER, ONCE IT IS IN THE ADDRESS BOOK — the branch flips, and it is the DAEMON that looks it up", async () => {
    /**
     * Nothing about the message changes between this test and the one above. The only difference is
     * a row in the operator's own address book, which is the whole design: the signal the reach-out
     * branch turns on is one the sender cannot cause from the wire.
     */
    handle = await startDaemon(await config());
    handle.getSessionNodeManager().addContact("alice", SIGNER_HEX, "Bob");
    seedTranscript("s-known");
    const n = await refuse("s-known", Buffer.from(SIGNER_HEX, "hex"));
    expect(n.guidance, "reaching out is offered — in a NEW conversation").toMatch(/open a NEW conversation with/);
    expect(n.impact, "and the operator's own name for the key is used").toMatch(/"Bob"/);
    expect(n.impact, "possession, never identity").toMatch(/does NOT prove they are "Bob"/);
    expect(n.impact, "the local trace is read from OUR transcript, not from the sender's claim")
      .toMatch(/still holds part of a conversation under that id/);
    expect(n.guidance).toContain(WHEN_IN_DOUBT);
  });

  it("A KNOWN KEY WITH A MIXED-CASE CONTACT ROW IS STILL KNOWN — hex case must not silently strand a contact", async () => {
    /**
     * `contacts.pubkey` is stored verbatim from the IPC parameter and is never case-normalized, so a
     * case-sensitive lookup would report a contact the operator can SEE in `cello_contacts` as an
     * unknown stranger. The failure direction is safe (report) and the notice would still be wrong.
     */
    handle = await startDaemon(await config());
    handle.getSessionNodeManager().addContact("alice", SIGNER_HEX.toUpperCase(), "Bob");
    const n = await refuse("s-mixedcase", Buffer.from(SIGNER_HEX, "hex"));
    expect(n.guidance, "the address book holds this key; case is not a difference in identity")
      .toMatch(/open a NEW conversation with/);
  });
});
