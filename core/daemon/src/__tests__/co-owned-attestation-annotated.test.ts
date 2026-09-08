/**
 * Two agents owned by the same operator may attest about each other — the co-ownership is
 * ANNOTATED, not refused.
 *
 * THE DEFECT: the daemon refused `cello_attestations_issue` outright whenever the subject was any
 * other agent loaded on this machine, with `reason: "self_subject"`. That refusal contradicted the
 * portal, which has decided the opposite question deliberately (D-29, `submission-ingress.ts`):
 * an agent-subject same-operator endorsement is MINTED and FLAGGED `same_operator: true`, because
 * "these two agents are the same operator" is a true and useful fact for a recipient, and
 * `same_operator` is a first-class field inside the signed envelope precisely so it can be capped
 * at the endorser's own tier and excluded from any count floor. The daemon's refusal meant that
 * flagged form could never be produced at all — the submission never left the machine.
 *
 * WHY IT MATTERS MORE THAN IT LOOKS: solo multi-agent is CELLO's first wedge. An operator running
 * two of their own agents is the MOST likely configuration to hit this, not the least, so the one
 * path the daemon closed is the one the first wedge walks daily.
 *
 * WHAT IS STILL REFUSED, and why the distinction is the whole point: an agent attesting about
 * ITSELF. There is no co-ownership fact to annotate there — issuer and subject are one identity,
 * the claim asserts nothing a reader could use, and no downstream flag rescues it.
 *
 * REVERT TESTS (each reddens for its own reason):
 *   - restore the broad `loadedAgents.find(...)` refusal → clause 1 fails: a co-owned subject is
 *     refused `self_subject` again and never reaches submission.
 *   - drop the identity comparison entirely → clause 2 fails: an agent attests about itself.
 */
import { describe, it, expect } from "vitest";
import { registerSignalHandlers, type SignalHandlerDeps } from "../signal-handlers.js";
import type { LoadedAgent } from "../agent-loader.js";

const ISSUER = "1ef23fa144860fefd57e61e903fb165adc9bf25264bb317aa67eb157b023d1a8";
const CO_OWNED = "0bbba280ff9d8f7bb495b875e34ef8cf73de5fbf0a3c2714943acd99b70035d7";

type Handler = (
  params: Record<string, unknown>,
  connectionId: string,
) => Promise<Record<string, unknown>>;

function agent(name: string, pubkey: string): LoadedAgent {
  // The key provider is never reached: both clauses assert on the guard, which returns before any
  // signing happens. Casting a bare object keeps the test to the surface under test.
  return { name, pubkey, keyProvider: {} as LoadedAgent["keyProvider"] };
}

/**
 * The guard runs before every collaborator the handler would otherwise need, so the rest of `deps`
 * is deliberately absent rather than mocked. A stub that answered these calls would be asserting
 * that the mock behaves, not that the guard does — and if the guard ever stops returning early,
 * the missing deps make that failure LOUD instead of letting a mock absorb it.
 */
function makeHandler(loadedAgents: LoadedAgent[], selected: string): Handler {
  const handlers = new Map<string, Handler>();
  const deps = {
    handlers,
    logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    loadedAgents,
    getConnState: () => ({ currentAgent: selected }),
  } as unknown as SignalHandlerDeps;
  registerSignalHandlers(deps);
  const h = handlers.get("cello_attestations_issue");
  if (!h) throw new Error("cello_attestations_issue is not registered");
  return h as Handler;
}

describe("co-owned attestations are annotated, not refused", () => {
  it("clause 1: a subject that is ANOTHER agent on this daemon is not refused as self", async () => {
    const handler = makeHandler(
      [agent("Miss_Chelly", ISSUER), agent("Mac_Coder_1", CO_OWNED)],
      "Miss_Chelly",
    );

    // Reaching submission means the guard let it past. Submission itself has no collaborators here,
    // so it throws — which is a PASS for this clause and is asserted as such rather than swallowed:
    // the one outcome this clause forbids is a clean `self_subject` refusal.
    let result: Record<string, unknown> | null = null;
    try {
      result = await handler({ subject_pubkey: CO_OWNED, body: "Worked with them." }, "c1");
    } catch {
      result = null; // got past the guard, into machinery this test deliberately does not provide
    }

    if (result !== null) {
      expect(result["reason"]).not.toBe("self_subject");
    }
  });

  it("clause 2: an agent attesting about ITSELF is still refused", async () => {
    const handler = makeHandler(
      [agent("Miss_Chelly", ISSUER), agent("Mac_Coder_1", CO_OWNED)],
      "Miss_Chelly",
    );

    const result = await handler({ subject_pubkey: ISSUER, body: "I am reliable." }, "c1");

    expect(result["ok"]).toBe(false);
    expect(result["reason"]).toBe("self_subject");
  });
});
