import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { buildSubmissionTbs, decodeSubmission, encodeSubmission, type SubmissionBody } from "@cello-protocol/protocol-types";

const here = dirname(fileURLToPath(import.meta.url));

/**
 * M10B-D4 / DOD-END-SURFACE-1 — the refusal message.
 *
 * Alice refuses an endorsement Bob wrote about her and MAY tell him why. The decision and the
 * courtesy are separate facts, and the tests below pin the separation from both directions.
 */
describe("M10B-D4 — refusing with a message", () => {
  const daemon = readFileSync(resolve(here, "../daemon.ts"), "utf8");
  const handler = (() => {
    const start = daemon.indexOf('handlers.set("cello_consent_refuse"');
    expect(start, "cello_consent_refuse is registered").toBeGreaterThan(-1);
    const next = daemon.indexOf("handlers.set(", start + 1);
    return daemon.slice(start, next === -1 ? daemon.length : next);
  })();

  it("records the refusal BEFORE anything that can fail — a refusal never depends on the network", () => {
    // The ordering IS the invariant: if the send were attempted first and threw, Alice would have
    // refused a signal that is still pending. Assert the positions, not the prose. The send now
    // lives in `submitForAgent` (shared with the issue verb), so the ordering to assert is
    // "recorded, THEN handed to the submission path".
    const setRefused = handler.indexOf('setConsentState(item.signalHash, "refused")');
    const submit = handler.indexOf("submitForAgent(");
    expect(setRefused).toBeGreaterThan(-1);
    expect(submit).toBeGreaterThan(setRefused);
  });

  it("returns the refusal on EVERY failure path — a failed message is not a failed refusal", () => {
    // Each early return in the message path spreads `refused`, so `ok: true` and the recorded state
    // survive. A path that returned `ok: false` would tell Alice her refusal did not happen when it
    // did — and she would try again on a signal that is already refused.
    const returns = [...handler.matchAll(/return \{ \.\.\.refused[^}]*\}/g)].map((m) => m[0]);
    expect(returns.length).toBeGreaterThanOrEqual(3); // no-message, account-subject, submit-failed, success
    for (const r of returns) expect(r).not.toMatch(/ok:\s*false/);
  });

  it("names the CAUSE of a failed message, never a generic exit label", () => {
    // §5a ERRORS NAME THEIR CAUSE: composeSealedSubmission's reason survives into the response
    // instead of collapsing to something like "send_failed", which would send an operator hunting
    // the network when the real cause is a manifest with no intake key.
    // The cause now arrives via the shared path's `reason`, which forwards composeSealedSubmission's
    // and sendSealedSubmission's verbatim — asserted on the helper below.
    expect(handler).toMatch(/message_error: res\.reason/);
    expect(handler).toMatch(/guidance: res\.guidance/);
  });

  it("treats an omitted, empty, or whitespace-only message as SILENCE", () => {
    // A silent refusal must tell Bob nothing — that is what keeps D-24 intact for anyone who wants
    // it. Sending "" would still deliver him a refusal notice, which is the opposite.
    expect(handler).toMatch(/\.trim\(\)/);
    expect(handler).toMatch(/message\.length === 0.*message_queued: false/s);
  });

  it("sends the message as the `refuse` op with the TARGET SIGNAL HASH as subject", () => {
    expect(handler).toMatch(/op: "refuse"/);
    expect(handler).toMatch(/subject: item\.signalHash/);
    // Never the endorsement body and never a type string — the discriminator is the protocol verb.
    expect(handler).not.toMatch(/"endorsement"/);
  });

  it("never claims the ISSUER was notified — a directory ack is not a delivery", () => {
    // `issuer_notified: true` asserted four steps that had not happened: the portal had not drained
    // the queue, scanned it, minted anything, or delivered anything. The only true statement at this
    // point is that a directory node accepted a sealed blob.
    expect(handler).not.toMatch(/issuer_notified:/);
    expect(handler).toMatch(/message_queued: true/);
    // And `stored` survives: it is the one signal separating a benign duplicate from single-node
    // censorship, and collapsing it into plain success destroys that distinction permanently.
    expect(handler).toMatch(/stored: res\.stored/);
  });

  it("the message is inside the signed TBS — the issuer cannot be shown different words", () => {
    const body: SubmissionBody = {
      v: 1, op: "refuse", subject_kind: "agent", subject: "c".repeat(64),
      submitter_pubkey: "d".repeat(64), body: "Please reissue without the migration claim.",
      issued_at: 1_800_000_100,
    };
    const tampered = { ...body, body: "Retracted, no objection." };
    expect(buildSubmissionTbs(tampered)).not.toEqual(buildSubmissionTbs(body));
    // And it survives the round trip byte-for-byte, so what Alice typed is what Bob reads.
    expect(decodeSubmission(encodeSubmission(body, new Uint8Array(64))).body.body).toBe(body.body);
  });
});

/**
 * The compose/seal/send path is now SHARED by `refuse` and `issue`. It is where every guard that
 * must hold for any submission lives, so it is asserted once, here — rather than re-asserted per
 * verb, which is how two paths that must agree stop agreeing.
 */
describe("submitForAgent — the guards every submission passes through", () => {
  const daemon = readFileSync(resolve(here, "../daemon.ts"), "utf8");
  const helper = (() => {
    const start = daemon.indexOf("async function submitForAgent(");
    expect(start, "submitForAgent exists").toBeGreaterThan(-1);
    return daemon.slice(start, daemon.indexOf("\n  handlers.set(", start));
  })();

  it("refuses to bring a STOPPED agent online as a side effect", () => {
    // getAgentSignaling CONSTRUCTS a manager when none exists — it dials and authenticates
    // immediately. The online check must come BEFORE it, or sending a message silently puts an
    // unstarted agent on the directory with no standing receiver behind it.
    const gate = helper.indexOf("onlineAgents.has(sel.name)");
    const signaling = helper.indexOf("getAgentSignaling(");
    expect(gate).toBeGreaterThan(-1);
    expect(signaling).toBeGreaterThan(gate);
  });

  it("caps the body before anything encodes, signs, or transmits it", () => {
    const cap = helper.indexOf("MAX_SUBMISSION_BODY_CHARS");
    expect(cap).toBeGreaterThan(-1);
    expect(helper.indexOf("composeSealedSubmission")).toBeGreaterThan(cap);
  });

  it("forwards the CAUSE from both compose and send, never a generic label", () => {
    expect(helper).toMatch(/reason: composed\.reason/);
    expect(helper).toMatch(/reason: sent\.reason/);
    expect(helper).toMatch(/stored: sent\.stored/);
  });

  it("takes the signing key from the SELECTED agent, with no way to name another", () => {
    // INV-ATTRIBUTION by construction: the provider is looked up from sel.name, and there is no
    // parameter through which a caller could pass a different identity.
    expect(helper).toMatch(/keyProviders\.get\(sel\.name\)/);
    expect(helper).not.toMatch(/opts\.(keyProvider|submitterPubkey)/);
  });
});
