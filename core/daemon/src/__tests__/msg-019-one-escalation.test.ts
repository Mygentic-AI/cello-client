/**
 * DOD-M12B-SEAL-ESCALATE-DUP-1 — there must be exactly ONE unilateral escalation.
 *
 * `daemon.ts`'s away/one-shot path is a line-for-line duplicate of `escalateToUnilateralSeal`, with
 * its own hardcoded 30-second timeout and its own waiter registration. **Every fix to the helper has
 * missed it**, and this milestone made four of them:
 *
 *   - the empty-carry refusal, so a session whose relay released it says so instead of waiting 30 s
 *     to be told nothing;
 *   - the gappy-chain refusal, same;
 *   - the duplicate-own-ctrl-leaf refusal, which is the permanently-unsealable case;
 *   - the bilateral-in-progress refusal, which stops us taking the worse receipt.
 *
 * The away path has none of them. It still spends the full timeout on every one of those cases and
 * then reports `seal_unilateral_timeout` — the label that names our own wait, which is this
 * milestone's founding error-fidelity defect.
 *
 * WHY THIS IS A SOURCE ASSERTION. The property is "one implementation exists", which is a property
 * of the source, not of any behaviour a single test could observe — and a behavioural test for the
 * away one-shot needs the whole inbox flow stood up to reach four lines. `startup-ordering.test.ts`
 * makes the same argument for the same reason: assert it where it lives rather than build a rig that
 * pins it by accident. Deliberately crude, and it has teeth — add a fourth copy and it goes red.
 *
 * Revert test: restore the inline escalation in `daemon.ts` and this fails with both file names.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const SRC = join(import.meta.dirname, "..");

/**
 * Every daemon source file, RECURSIVELY — a fourth copy dropped in a new subdirectory would sail
 * past a flat scan, and the property claimed here is "one implementation exists", not "one in this
 * directory".
 *
 * `__tests__` is excluded, and not for tidiness: THIS FILE contains both literal strings inside its
 * own `.includes(...)` arguments, so scanning itself would make the assertion self-defeating.
 */
function sources(): string[] {
  return readdirSync(SRC, { recursive: true, encoding: "utf-8" })
    .filter((f) => f.endsWith(".ts"))
    .filter((f) => !f.split(/[/\\]/).includes("__tests__"));
}

describe("DOD-M12B-SEAL-ESCALATE-DUP-1: one escalation, not three", () => {
  it("exactly one file constructs a seal_unilateral frame", () => {
    const builders = sources().filter((f) => readFileSync(join(SRC, f), "utf-8").includes('type: "seal_unilateral"'));

    expect(
      builders,
      "every fix to the escalation has to land in one place, or the copies drift — this milestone " +
      "shipped four refusals the away path never got, and each one costs a 30-second wait that " +
      "reports a timeout for a cause we already knew",
    ).toEqual(["seal-escalation.ts"]);
  });

  it("the escalation module is the only thing that registers a unilateral waiter", () => {
    // A second registrant is how the two copies diverged in the first place, and it is also how the
    // agent-scoped key introduced by DOD-M12B-SEAL-WAITER-KEY-1 gets forgotten in one of them.
    const registrants = sources().filter((f) => readFileSync(join(SRC, f), "utf-8").includes("pendingUnilateralWaiters.set("));

    expect(registrants, "one place registers, one place resolves").toEqual(["seal-escalation.ts"]);
  });
});
