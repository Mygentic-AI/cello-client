/**
 * 047-ENDORSETEXT — the endorsement body rule, checked before the body is signed.
 *
 * The portal is the authority. This exists so an honest mistake does not cost a round trip that
 * answers `scanner_charset` with a null message — which is what happened to a 926-character
 * endorsement rejected for its two paragraph breaks, with the blame landing on the punctuation.
 */
import { describe, it, expect } from "vitest";
import {
  ATTESTATION_DISALLOWED_CHARSET,
  ATTESTATION_LENGTH_CAP,
  checkAttestationBody,
  normalizeAttestationBody,
} from "../attestation-body.js";

describe("047-ENDORSETEXT — attestation body rule", () => {
  it("accepts a line break, which is the whole point of the change", () => {
    expect(checkAttestationBody("Reliable to work with.\n\nCaught two flaws in my plan.")).toBeNull();
  });

  it("refuses a tab, a control character and an angle bracket", () => {
    for (const body of ["a\tb", "ab", "a<b", "a>b"]) {
      expect(checkAttestationBody(body)?.reason, JSON.stringify(body)).toBe("body_disallowed_character");
    }
  });

  it("NAMES the character and its position, and says it was NOT sent", () => {
    // The portal's old message named a category, and an hour went to the wrong suspect. An
    // operator also has to know whether a copy is in flight before deciding to retry.
    const r = checkAttestationBody("Reliable <engineer>");
    expect(r?.guidance).toContain("'<'");
    expect(r?.guidance).toContain("position 9");
    expect(r?.guidance).toContain("Not sent");
  });

  it("refuses over the cap, naming the count and the limit", () => {
    const r = checkAttestationBody("a".repeat(ATTESTATION_LENGTH_CAP + 1));
    expect(r?.reason).toBe("body_too_long");
    expect(r?.guidance).toContain(String(ATTESTATION_LENGTH_CAP + 1));
    expect(r?.guidance).toContain("Not sent");
  });

  it("accepts exactly the cap", () => {
    expect(checkAttestationBody("a".repeat(ATTESTATION_LENGTH_CAP))).toBeNull();
  });

  it("normalises CRLF and a lone CR before signing, so a Windows body is not refused for an invisible character", () => {
    // This is the ONLY place the text can change and still be the text that was signed — the portal
    // receives it inside a signed submission and cannot rewrite it.
    expect(normalizeAttestationBody("a\r\nb")).toBe("a\nb");
    expect(normalizeAttestationBody("a\rb")).toBe("a\nb");
    expect(checkAttestationBody(normalizeAttestationBody("a\r\nb"))).toBeNull();
  });

  it("leaves a raw carriage return refusable, so a client that skips normalisation is still caught", () => {
    expect(checkAttestationBody("a\rb")?.reason).toBe("body_disallowed_character");
  });

  it("accepts non-English bodies — the rule only covers characters below U+0080", () => {
    // A rule that quietly became an ASCII gate would make CELLO an English-only product.
    for (const body of [
      "值得信赖的合作伙伴。",
      "信頼できるエージェントです。",
      "وكيل موثوق به.",
      "סוכן אמין.",
      "Надёжный агент.",
      "Reliable 👍",
      "Agent fiable — très cohérent.",
    ]) {
      expect(checkAttestationBody(body), body).toBeNull();
    }
  });

  it("counts CHARACTERS not bytes, so CJK gets the same allowance as English", () => {
    // A CJK glyph is three bytes in UTF-8; a byte cap would give this a third of the room.
    expect(checkAttestationBody("好".repeat(ATTESTATION_LENGTH_CAP))).toBeNull();
  });

  it("PINS THE RULE AGAINST ITS TWIN IN THE PORTAL", () => {
    /**
     * `cello-portal/src/server/trust/submission-scan.ts` holds the same two values as
     * `DISALLOWED_CHARSET` and `INTAKE_LENGTH_CAP`, and nothing at build time can compare them
     * across a repo boundary. That is the skew shape this milestone keeps finding — the same week,
     * `trust_signal_drain_complete` was typed independently in two repos with no shared constant.
     *
     * So each side pins the other by literal. The portal's suite carries the mirror of this
     * assertion. Change one without the other and a test fails, rather than an operator finding out
     * from a rejection.
     */
    expect(ATTESTATION_DISALLOWED_CHARSET.source).toBe("[\\x00-\\x09\\x0b-\\x1f\\x7f<>]");
    expect(ATTESTATION_LENGTH_CAP).toBe(500);
  });
});
