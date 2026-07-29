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
    // refused a signal that is still pending. Assert the positions, not the prose.
    const setRefused = handler.indexOf('setConsentState(item.signalHash, "refused")');
    const compose = handler.indexOf("composeSealedSubmission");
    const send = handler.indexOf("sendSealedSubmission");
    expect(setRefused).toBeGreaterThan(-1);
    expect(compose).toBeGreaterThan(setRefused);
    expect(send).toBeGreaterThan(setRefused);
  });

  it("returns the refusal on EVERY failure path — a failed message is not a failed refusal", () => {
    // Each early return in the message path spreads `refused`, so `ok: true` and the recorded state
    // survive. A path that returned `ok: false` would tell Alice her refusal did not happen when it
    // did — and she would try again on a signal that is already refused.
    const returns = [...handler.matchAll(/return \{ \.\.\.refused[^}]*\}/g)].map((m) => m[0]);
    expect(returns.length).toBeGreaterThanOrEqual(4); // no-message, no-key, compose-refused, send-failed, throw
    for (const r of returns) expect(r).not.toMatch(/ok:\s*false/);
  });

  it("names the CAUSE of a failed message, never a generic exit label", () => {
    // §5a ERRORS NAME THEIR CAUSE: composeSealedSubmission's reason survives into the response
    // instead of collapsing to something like "send_failed", which would send an operator hunting
    // the network when the real cause is a manifest with no intake key.
    expect(handler).toMatch(/message_error: composed\.reason/);
    expect(handler).toMatch(/message_error: sent\.reason/);
  });

  it("treats an omitted, empty, or whitespace-only message as SILENCE", () => {
    // A silent refusal must tell Bob nothing — that is what keeps D-24 intact for anyone who wants
    // it. Sending "" would still deliver him a refusal notice, which is the opposite.
    expect(handler).toMatch(/\.trim\(\)/);
    expect(handler).toMatch(/message\.length === 0.*issuer_notified: false/s);
  });

  it("sends the message as the `refuse` op with the TARGET SIGNAL HASH as subject", () => {
    expect(handler).toMatch(/op: "refuse"/);
    expect(handler).toMatch(/subject: item\.signalHash/);
    // Never the endorsement body and never a type string — the discriminator is the protocol verb.
    expect(handler).not.toMatch(/"endorsement"/);
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
