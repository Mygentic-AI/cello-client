/**
 * What an endorsement body may contain — checked HERE, before it is signed and sent.
 *
 * ─── WHY THIS EXISTS ON THE CLIENT AT ALL ─────────────────────────────────────────────────────
 *
 * The portal is the authority and stays the authority: a client can be edited, so anything only the
 * client enforces is not enforced. This is not enforcement. It is the difference between learning
 * the rule now and learning it after a round trip that answers `scanner_charset` with no message.
 *
 * That round trip really happened (047-ENDORSETEXT): a 926-character endorsement was rejected for
 * its two paragraph breaks, the refusal named a category rather than a character, and the blame
 * landed on the punctuation for an hour.
 *
 * ─── THE RULE IS DEFINED IN TWO REPOSITORIES AND THAT IS A HAZARD ─────────────────────────────
 *
 * The portal's copy is `DISALLOWED_CHARSET` / `INTAKE_LENGTH_CAP` in
 * `cello-portal/src/server/trust/submission-scan.ts`. They must agree, and nothing at build time
 * can check that across a repo boundary — the same skew shape as `trust_signal_drain_complete`.
 *
 * **So each side pins the other in a test.** `attestation-body.test.ts` asserts these exact values
 * and names its twin; the portal's `m10b-scan-1-submission-scan.test.ts` does the same. Change one
 * without the other and a test fails rather than an operator discovering it.
 */

/** Characters below U+0080 that may not appear. Everything above passes — non-English bodies are
 *  legal and this rule must never become an ASCII gate. `\n` is allowed; a tab is not. */
export const ATTESTATION_DISALLOWED_CHARSET = /[\x00-\x09\x0b-\x1f\x7f<>]/;

/** CHARACTERS, not bytes: a byte cap gives a Chinese endorsement a third of the room. */
export const ATTESTATION_LENGTH_CAP = 500;

/**
 * Normalise line endings BEFORE signing, because this is the only place the text can change and
 * still be the text that was signed. The portal cannot do it — the body arrives inside a signed
 * submission, so rewriting it there would invalidate the signature that makes it attributable.
 */
export function normalizeAttestationBody(body: string): string {
  return body.replace(/\r\n?/g, "\n").trim();
}

export interface BodyRefusal {
  reason: "body_too_long" | "body_disallowed_character";
  guidance: string;
}

/**
 * Returns a refusal, or null when the body is acceptable.
 *
 * Every guidance string says three things, in this order: that it was NOT sent, what exactly is
 * wrong, and what to do. The first matters most — an operator who cannot tell whether a copy is in
 * flight will either resend a duplicate or wait for something that never left.
 */
export function checkAttestationBody(body: string): BodyRefusal | null {
  if (body.length > ATTESTATION_LENGTH_CAP) {
    return {
      reason: "body_too_long",
      guidance:
        `Not sent — nothing left this machine. The body is ${body.length} characters and the limit ` +
        `is ${ATTESTATION_LENGTH_CAP}. An endorsement is a testimonial, not a document: say the one ` +
        `thing you would want a stranger to know, and run cello_attestations_issue again.`,
    };
  }
  const index = body.search(ATTESTATION_DISALLOWED_CHARSET);
  if (index >= 0) {
    const code = body.charCodeAt(index);
    const named =
      code === 0x09 ? "a tab" :
      code === 0x0d ? "a carriage return" :
      code === 0x3c ? "a '<'" :
      code === 0x3e ? "a '>'" :
      `U+${code.toString(16).toUpperCase().padStart(4, "0")}`;
    return {
      reason: "body_disallowed_character",
      guidance:
        `Not sent — nothing left this machine. The body contains ${named} at position ${index}. ` +
        `Line breaks are fine; other control characters and angle brackets are not, because they ` +
        `hide content from a reader while a parser still sees it. Remove it and run ` +
        `cello_attestations_issue again.`,
    };
  }
  return null;
}
