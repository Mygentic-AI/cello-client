/**
 * A co-owned endorsement is READABLE as words, not only as a boolean nobody displayed.
 *
 * THE GAP: `same_operator` is envelope slot 12 — inside the notarized hash, unforgeable, and the
 * only thing a recipient's floor predicate may read. All correct, and all invisible. The wallet LIST
 * showed a `co-own` column; `wallet_view_signal` — the verb whose entire job is "show me the claim I
 * am being asked to stand behind" — returned issuer, subject, payload and dates, and NOT this. So
 * the one surface built for judging an endorsement omitted the one fact that decides its worth.
 *
 * TWO SOURCES, AND WHICH ONE DECIDES. The portal writes a rendered sentence into the payload
 * (`co_ownership_note`, added the same day). That is DISPLAY: payload shape is per-type and a signal
 * minted before the note existed will never carry it. The BOOLEAN is the authority and is always
 * present, which is why the handler returns it and the CLI line is driven by it.
 *
 * ONE WORDING, ONE HOME. `CO_OWNERSHIP_NOTE` lives in `@cello-protocol/protocol-types` because the
 * portal that mints it and the client that prints it would otherwise drift into two sentences for
 * one fact — the same reason the envelope codec itself is shared (M10-D16).
 *
 * REVERT TESTS:
 *   - drop `same_operator` from the handler's return → clause 1 fails: the read verb hides it again.
 *   - reword either copy of the note → clause 3 fails: the two repos disagree about one fact.
 */
import { describe, it, expect } from "vitest";
import { CO_OWNERSHIP_NOTE } from "@cello-protocol/protocol-types";

describe("co-ownership is surfaced where an endorsement is read", () => {
  it("clause 1: wallet_view_signal returns the envelope flag", async () => {
    // Asserted against the SOURCE rather than a constructed handler: the view verb builds its result
    // from a store row, and a stub store would only prove the stub returns what it was given. What
    // must hold is that the field is in the response shape at all — that is what was missing.
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(new URL("../signal-handlers.ts", import.meta.url), "utf8");
    const viewBody = src.slice(src.indexOf('handlers.set("wallet_view_signal"'), src.indexOf('handlers.set("wallet_enable_signal"'));
    expect(viewBody).toContain("same_operator: row.sameOperator");
  });

  it("clause 2: the CLI prints the note, and drives it off the BOOLEAN not the payload", async () => {
    const { readFileSync } = await import("node:fs");
    const cli = readFileSync(new URL("../../../cli/src/commands.ts", import.meta.url), "utf8");
    expect(cli).toContain("result.same_operator === true");
    expect(cli).toContain("CO_OWNERSHIP_NOTE");
    // The note must not be reconstructed locally — that is the drift this shares a constant to avoid.
    expect(cli).not.toContain("does not count toward endorsement minimums\"");
  });

  it("clause 3: the wording says the fact AND the consequence, and claims no ownership between them", () => {
    expect(CO_OWNERSHIP_NOTE).toBe(
      "[endorsed by an agent with the same owner — does not count toward endorsement minimums]",
    );
    // `same_operator` means both agents share an OWNER — siblings, not parent and child. Wording
    // that said one endorser owned the other would assert what the flag cannot support.
    expect(CO_OWNERSHIP_NOTE).not.toMatch(/owns/i);
  });
});
