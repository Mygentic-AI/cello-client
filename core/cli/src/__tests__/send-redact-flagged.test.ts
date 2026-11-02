/**
 * `cello send --redact-flagged` — a flagged message goes out with the value masked, not lost.
 *
 * Without it, a script calling `cello send` has no way to answer a privacy warning, so the whole
 * message is dropped. In a live run on 2026-11-02 that lost 14 of 85 reports, most of them commits.
 *
 * What these pin: the only decision ever sent is `redact`, so the flag can never let a value out. It
 * resends once, only on a warning it can answer, and anything else comes back untouched.
 *
 * The daemon and gateway half of a redact re-send is proven against real processes in the daemon's
 * m9-core-001-seam test. This file proves the CLI's half, which is why a scripted client is enough.
 */
import { describe, it, expect } from "vitest";
import { sendRedactingFlagged } from "../parity-commands.js";
import { COMMANDS } from "../registry.js";

type Reply = Record<string, unknown>;

function scriptedClient(replies: Reply[]) {
  const calls: Array<{ method: string; params: Reply }> = [];
  return {
    calls,
    send: async (method: string, params?: Reply) => {
      calls.push({ method, params: params ?? {} });
      const next = replies.shift();
      if (!next) throw new Error("the client was called more times than the test scripted");
      return next;
    },
  };
}

const PARAMS = { session_id: "abc", content: "write to someone@example.org [[OVER]]" };
const warn = (flags: unknown[]): Reply => ({ ok: false, reason: "governance_warn", guidance: "held", flags });
const FLAG_A = { stage: "pii", disposition: "warn", category: "pii:email", flagId: "aaa" };
const FLAG_B = { stage: "pii", disposition: "warn", category: "pii:phone", flagId: "bbb" };
const SENT = { ok: true, sequence_number: 4, modified: true, witnessed: true };

describe("sendRedactingFlagged", () => {
  it("sends a clean message once and returns the reply untouched", async () => {
    const client = scriptedClient([SENT]);
    const out = await sendRedactingFlagged(client, PARAMS);
    expect(client.calls).toHaveLength(1);
    expect(client.calls[0]!.params).toEqual(PARAMS);
    expect(out).toEqual(SENT);
  });

  it("on a warning, resends the same content with every flag set to redact", async () => {
    const client = scriptedClient([warn([FLAG_A, FLAG_B]), SENT]);
    await sendRedactingFlagged(client, PARAMS);
    expect(client.calls).toHaveLength(2);
    expect(client.calls[0]!.params).toEqual(PARAMS);
    expect(client.calls[1]).toEqual({
      method: "cello_send",
      params: { ...PARAMS, governance_decisions: { aaa: "redact", bbb: "redact" } },
    });
  });

  it("says what it masked, by category and never by value", async () => {
    const client = scriptedClient([warn([FLAG_A, FLAG_B]), SENT]);
    const out = await sendRedactingFlagged(client, PARAMS);
    expect(out).toEqual({ ...SENT, redacted_flags: ["pii:email", "pii:phone"] });
    expect(JSON.stringify(out)).not.toContain("someone@example.org");
  });

  it("never sends any decision except redact", async () => {
    const client = scriptedClient([warn([FLAG_A, FLAG_B]), SENT]);
    await sendRedactingFlagged(client, PARAMS);
    const decisions = client.calls[1]!.params["governance_decisions"] as Reply;
    expect(new Set(Object.values(decisions))).toEqual(new Set(["redact"]));
  });

  it("does not resend a refusal that is not a privacy warning", async () => {
    const refused = { ok: false, reason: "session_not_current", unread_received: 1 };
    const client = scriptedClient([refused]);
    expect(await sendRedactingFlagged(client, PARAMS)).toEqual(refused);
    expect(client.calls).toHaveLength(1);
  });

  it("does not resend a block, which redacting cannot answer", async () => {
    const blocked = { ok: false, reason: "blocked_by_governance", blocks: [{ category: "injection" }] };
    const client = scriptedClient([blocked]);
    expect(await sendRedactingFlagged(client, PARAMS)).toEqual(blocked);
    expect(client.calls).toHaveLength(1);
  });

  it("returns the warning unsent when any flag has no id it could answer", async () => {
    const malformed = warn([FLAG_A, { category: "pii:phone" }]);
    const client = scriptedClient([malformed]);
    expect(await sendRedactingFlagged(client, PARAMS)).toEqual(malformed);
    expect(client.calls).toHaveLength(1);
  });

  it("returns the warning unsent when it names no flags", async () => {
    const empty = warn([]);
    const client = scriptedClient([empty]);
    expect(await sendRedactingFlagged(client, PARAMS)).toEqual(empty);
    expect(client.calls).toHaveLength(1);
  });

  it("resends once: a second warning comes back rather than looping", async () => {
    const second = warn([FLAG_B]);
    const client = scriptedClient([warn([FLAG_A]), second]);
    expect(await sendRedactingFlagged(client, PARAMS)).toEqual(second);
    expect(client.calls).toHaveLength(2);
  });
});

describe("`cello send --redact-flagged` is a declared flag", () => {
  const sendCommand = COMMANDS.find((c) => c.name === "send")!;

  it("is accepted by the argument check and takes no value", () => {
    expect(sendCommand.flags).toContainEqual({ name: "--redact-flagged", consumesValue: false });
  });

  it("is described in the help", () => {
    expect(sendCommand.help).toContain("--redact-flagged");
  });
});
