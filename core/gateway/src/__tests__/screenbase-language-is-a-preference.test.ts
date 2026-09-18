/**
 * DOD-M9C-SCREENBASE-1 — language is a preference, not a screen.
 *
 * It used to block by default and refused 554 of 5,000 ordinary benign messages — 11% of real
 * traffic — because it counts which alphabet the letters come from and cannot tell a Chinese
 * purchase order from a Chinese jailbreak. Measured 2026-09-18, the classifier refuses 5 of those
 * same 554 and caught every non-Latin attack in the corpus.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { InboundScreener } from "../screen/inbound.js";
import { initLinearRegex } from "../detect/linear-regex.js";
import { compileInjectionPatterns } from "../detect/injection-patterns.js";

const enc = (s: string) => new TextEncoder().encode(s);
/** Real benign messages from the bordair benign set — the traffic the old default refused. */
const CHINESE = "鄂尔多斯市鄂托克旗棋盘井镇工业园区鄂绒硅铁五公司的位置在哪里呢";
const RUSSIAN = "А непродолжительный контакт может навредить организму человека?";
const GREEK = "καλημέρα, θα ήθελα να ρωτήσω για το συμβόλαιο που στείλατε χθες";

describe("DOD-M9C-SCREENBASE-1 — language no longer refuses ordinary mail", () => {
  beforeAll(async () => { await initLinearRegex(); compileInjectionPatterns(); });

  it("an ordinary message in Chinese, Russian or Greek is DELIVERED by default", async () => {
    for (const text of [CHINESE, RUSSIAN, GREEK]) {
      const v = await new InboundScreener().screen(enc(text));
      expect(v.disposition).not.toBe("block");
      expect(v.terminal).toBeUndefined();
      expect(v.reason).not.toBe("inbound_language_blocked");
    }
  });

  it("the agent is TOLD it got one layer of screening, not two — silence would read as clean", async () => {
    const v = await new InboundScreener().screen(enc(RUSSIAN));
    const note = v.events.find((e) => String(e.category).startsWith("language:"));
    expect(note?.disposition).toBe("observe");
    expect(note?.reason).toContain("English-only");
  });

  it("real Greek is delivered as WRITTEN — the product must not rewrite someone's language", async () => {
    const v = await new InboundScreener().screen(enc(GREEK));
    expect(new TextDecoder().decode(v.content)).toBe(GREEK);
  });

  it("an operator who wants English-only mail still gets the refusal, and it names the way back", async () => {
    const v = await new InboundScreener({ languageEnforce: true }).screen(enc(RUSSIAN));
    expect(v.disposition).toBe("block");
    expect(v.terminal).toBe(true);
    expect(v.reason).toBe("inbound_language_blocked");
    expect(v.guidance).toContain("language_allow");
  });

  it("enforcing with a WIDER allowlist delivers that language and still refuses the others", async () => {
    const screener = new InboundScreener({ languageEnforce: true, language: { allow: ["latin", "cyrillic"] } });
    expect((await screener.screen(enc(RUSSIAN))).disposition).not.toBe("block");
    expect((await screener.screen(enc(CHINESE))).disposition).toBe("block");
  });
});
