/**
 * A HASH IS NOT A PHONE NUMBER, and agents send hashes constantly.
 *
 * Reported from a live run on 2026-11-02: a report carrying only a transcript hash was refused
 * because `f512e19086cd2cfb857081282ab2…` contains the digits `857081282`, and `PHONE_RE` is the one
 * pattern with no word boundary. Whether a message went through depended on what a hash happened to
 * contain, so any agent quoting a commit, a seal or a session id could be refused at random.
 *
 * These assert the exclusion is narrow: long hex tokens and UUIDs stop warning, and a real phone
 * number beside one, or inside anything shorter, still does.
 */
import { describe, it, expect } from "vitest";
import { OutboundPIIScreener } from "../detect/pii.js";

const screener = new OutboundPIIScreener({ whitelist: [] });
const screen = (t: string) => screener.screen(new TextEncoder().encode(t), `s-${Math.random()}`);
const cats = (t: string): string[] => screen(t).events.map((e) => e.category);

const SHA256 = "f512e19086cd2cfb857081282ab2fac86e5f182a8de18ad7219ad742a54a57bb";
const SHA1 = "a1b2c3d4e5f6415555526710000000000000abcd";
const SESSION_ID = "d6297be0293ceb6ea00ad9fbf0cb5ed1".replace("0293", "4155552671").slice(0, 32);
const UUID = "6bbefd5b-8592-4190-9412-fa7df7d8f944";

describe("the phone rule does not fire on hashes agents actually send", () => {
  it("does NOT flag digits inside a SHA-256 hash", () => {
    expect(cats(`transcript ${SHA256} stored`)).not.toContain("pii:phone");
  });

  it("does NOT flag digits inside a SHA-1 commit hash", () => {
    expect(cats(`commit ${SHA1} pushed`)).not.toContain("pii:phone");
  });

  it("does NOT flag digits inside a 32-character session id", () => {
    expect(cats(`session ${SESSION_ID}`)).not.toContain("pii:phone");
  });

  it("does NOT flag the all-digit middle of a UUID", () => {
    expect(cats(`claude_session ${UUID}`)).not.toContain("pii:phone");
  });

  it("does NOT flag a hash in the JSON shape reports use", () => {
    expect(cats(JSON.stringify({ sha256: SHA256, uuid: UUID, sha: SHA1 }))).not.toContain("pii:phone");
  });
});

describe("a real phone number near a hash is still a phone number", () => {
  it("FLAGS a number after a hash, and reports only the number", () => {
    const events = screen(`${SHA256} 415-555-2671`).events.filter((e) => e.category === "pii:phone");
    expect(events.map((e) => e.value)).toEqual(["415-555-2671"]);
  });

  it("FLAGS a number before a hash", () => {
    expect(cats(`415-555-2671 ${SHA256}`)).toContain("pii:phone");
  });

  it("FLAGS a number joined to a hash by punctuation", () => {
    expect(cats(`${SHA256}-4155552671`)).toContain("pii:phone");
    expect(cats(`${SHA256}:4155552671`)).toContain("pii:phone");
    expect(cats(`${UUID}-4155552671`)).toContain("pii:phone");
  });

  it("FLAGS a number in a hex token too short to be a hash", () => {
    expect(cats("ref a4155552671b end")).toContain("pii:phone");
    expect(cats(`ref ${"a4155552671b".padEnd(31, "0")} end`)).toContain("pii:phone");
  });

  it("FLAGS a long run of digits with no hex letter: padding must not hide a number", () => {
    expect(cats(`ref 4155552671${"0".repeat(30)} end`)).toContain("pii:phone");
  });

  it("FLAGS an all-digit value in the shape of a UUID", () => {
    // Any category will do: this one also reads as a card number, and either way it is not sent silently.
    expect(cats("ref 41555526-7100-0000-0000-000000000000 end").length).toBeGreaterThan(0);
  });

  it("does not hide an email that sits next to a hash", () => {
    expect(cats(`${SHA256} someone@example.org`)).toContain("pii:email");
  });
});
