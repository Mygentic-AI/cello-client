/**
 * DOD-TERMINAL-STATE-DIVERGENCE-1 — a close that fails must ASK whether the seal already happened.
 *
 * ── THE SITUATION, IN THE OPERATOR'S WORDS ───────────────────────────────────────────────────────
 *
 * The notarization confirmation is SENT to you once. If your connection is down at that instant it
 * is gone — the re-delivery queue is per-node and clients roam between nodes, so reconnecting
 * somewhere else drains an empty queue.
 *
 * The conversation IS notarized. Your counterparty holds a receipt. You hold a session that still
 * looks unfinished, and every close you run fails in a way indistinguishable from "the seal has not
 * happened yet". The documented endpoint of that loop is a force-abandon, which PERMANENTLY forfeits
 * your half of a receipt that already exists.
 *
 * ── WHAT THIS PINS ───────────────────────────────────────────────────────────────────────────────
 *
 * The ability to ask already existed and was wired to exactly one place: reading a receipt. It was
 * not wired to the CLOSE, which is where an operator actually gets stuck — they are not reading a
 * receipt, they are trying to end a conversation.
 *
 * So: a close that fails for a reason that could mean "already sealed elsewhere" asks once, and if a
 * certificate comes back AND VERIFIES, the close succeeds and hands over the receipt.
 *
 * ── THE TWO THINGS THAT MUST NOT DRIFT ───────────────────────────────────────────────────────────
 *
 * 1. It asks only on reasons where the seal could plausibly already exist. Asking on every failure
 *    would put a directory round trip in front of ordinary refusals — including the ones that fail
 *    precisely because nothing has been sealed.
 * 2. "We asked and there is none" is REPORTED, distinctly from "we never asked". An operator weighing
 *    a force-abandon — the irreversible one — needs to know which of the two they are holding.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

const SRC = readFileSync(new URL("../close-session-handler.ts", import.meta.url), "utf8");
const ROOT = readFileSync(new URL("../daemon.ts", import.meta.url), "utf8");

describe("the close can ask, and is wired to do so", () => {
  it("the composition root gives the close handler the pull", () => {
    // The seam where a fully-built capability stays invisible: nothing fails if it is simply never
    // passed in. Exactly how the ability to ask sat unused on this path in the first place.
    const closeBlock = ROOT.slice(ROOT.indexOf("registerCloseSessionHandler({"));
    expect(
      /pullSealCertificate:\s*\(agentName: string, sessionIdHex: string\)/.test(closeBlock.slice(0, 2000)),
      "the close handler cannot ask — the pull exists but was not handed to it",
    ).toBe(true);
  });

  it("asks only on reasons that could mean the seal already exists", () => {
    const set = /MAY_ALREADY_BE_SEALED = new Set\(\[([\s\S]*?)\]\)/.exec(SRC);
    expect(set, "the reason list was renamed or removed").not.toBeNull();
    const reasons = [...set![1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]!);

    // The counterparty rejecting our seal request is the signature case: it rejects because it
    // considers the session finished, which IS the divergence.
    expect(reasons).toContain("seal_interrupted_rejected_by_counterparty");
    // No answer at all — the push we missed may have been the answer.
    expect(reasons).toContain("seal_unilateral_timeout");
    // The relay calling the session terminal means whatever exists is final.
    expect(reasons).toContain("session_sealed");

    // And NOT the ones where asking is noise on a settled question.
    for (const never of ["invalid_session_id", "session_not_found", "no_current_agent", "session_already_abandoned"]) {
      expect(reasons, `'${never}' is already answered — asking would be a round trip for nothing`).not.toContain(never);
    }
  });

  it("reports 'asked, none exists' distinctly from never having asked", () => {
    // The distinction an operator needs before doing the irreversible thing.
    expect(SRC).toContain("seal_lookup");
    expect(SRC).toContain("asked_none_exists");
    expect(/seal\.certificate\.pull\.none_on_close/.test(SRC)).toBe(true);
  });

  it("a recovered certificate turns the FAILED close into a receipt", () => {
    expect(/seal\.certificate\.recovered_on_close/.test(SRC)).toBe(true);
    // ok:true and the root — not merely a nicer error. The operator asked to close and now has what
    // closing was for.
    const recovered = SRC.slice(SRC.indexOf("recovered_on_close"));
    expect(recovered.slice(0, 900)).toContain("sealed_root");
    expect(recovered.slice(0, 900)).toContain("ok: true");
  });

  it("reads the IPC parameter name, not the MCP tool's name", () => {
    // A real bug caught by the vocabulary audit while writing this: the wrapper first read
    // `cello_session_id`, which is what the MCP TOOL takes. The shim translates it, so over IPC the
    // field is `session_id` — the wrapper would have found nothing and skipped every recovery, and
    // no test would have failed for it.
    const wrapper = SRC.slice(SRC.indexOf("const closeSession ="), SRC.indexOf("handlers.set(\"cello_close_session\""));
    expect(wrapper).toContain("params?.session_id");
    // The ACCESS, not the prose. The comment above that line names the MCP field deliberately, so a
    // bare substring check would fail on the explanation of the very bug it is guarding.
    expect(/params\?\.cello_session_id/.test(wrapper), "reads the MCP field name over IPC — finds nothing").toBe(false);
  });
});
