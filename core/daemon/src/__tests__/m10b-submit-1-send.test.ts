/**
 * M10B / DOD-END-SUBMIT-1 — handing a sealed submission to a directory node.
 *
 * The send half. Its job is small and its failure modes are the interesting part: the daemon holds
 * ONE signaling stream to ONE node (verified — registration sends `register_request` to that node
 * and the DIRECTORY fans out to the quorum; there is no client-side multi-node write path), so
 * "failover" here is the SignalingManager's existing reconnect, and a retry after it is safe
 * precisely because `submission_id` is content-derived (M10B-D20).
 *
 * Two failure modes get specific attention because both are silent by default:
 *   - VERSION SKEW. A directory node that has not deployed this frame kind replies
 *     `not_authenticated` (its decoder returns null). Reporting that verbatim sends an operator to
 *     debug KEYS for a day over a rollout artefact — the ERROR SUBSTITUTION trap (§5b Lens 3a2).
 *     Directory nodes are sovereign and deploy per region, so this is the NORMAL rollout case.
 *   - DUPLICATE. `stored: false` means an id was already present. Usually the submitter's own retry,
 *     and also the shape of a single-node censorship attack (Entry 20), so it must never be
 *     collapsed into plain success.
 */
import { describe, it, expect } from "vitest";
import { sendSealedSubmission } from "../signal-submission.js";
import type { Logger } from "../types.js";

const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
const recording: Logger = {
  debug() {},
  info(event: string, ctx?: Record<string, unknown>) { events.push({ event, ctx: ctx ?? {} }); },
  warn(event: string, ctx?: Record<string, unknown>) { events.push({ event, ctx: ctx ?? {} }); },
  error(event: string, ctx?: Record<string, unknown>) { events.push({ event, ctx: ctx ?? {} }); },
};

const SUBMISSION = {
  submissionId: "ab".repeat(32),
  intakeKeyId: "intake-2026-07",
  ciphertext: new Uint8Array([1, 2, 3, 4]),
};

/** A signaling stub that replies with whatever frame the test names, as the directory would. */
function signalingThatReplies(reply: Record<string, unknown> | null, sendResult = { ok: true as const }) {
  const handlers: Array<(f: Record<string, unknown>) => void> = [];
  return {
    // EXPOSED so the unregister test can observe the leak it is named for. Previously it asserted
    // only that registerInboundHandler RETURNED a function — true of any stub — and passed with
    // `finally { unregister() }` deleted.
    handlers,
    sent: [] as unknown[],
    async sendRaw(frame: unknown) {
      this.sent.push(frame);
      if (reply) queueMicrotask(() => handlers.forEach((h) => h(reply)));
      return sendResult;
    },
    registerInboundHandler(h: (f: Record<string, unknown>) => void) {
      handlers.push(h);
      return () => { handlers.splice(handlers.indexOf(h), 1); };
    },
  };
}

const send = (signaling: ReturnType<typeof signalingThatReplies>, timeoutMs = 200) =>
  sendSealedSubmission({ signaling, ...SUBMISSION, logger: recording, timeoutMs });

describe("DOD-END-SUBMIT-1 — the submission_write frame", () => {
  it("sends exactly the three queue columns and nothing that could identify the parties", async () => {
    // The queue's privacy property is structural: the directory has nowhere to put anything it
    // learned. If the FRAME carried a submitter or a subject, the table would want a column for it.
    const s = signalingThatReplies({ type: "submission_write_result", submission_id: SUBMISSION.submissionId, stored: true });
    await send(s);
    const frame = s.sent[0] as Record<string, unknown>;
    expect(frame["type"]).toBe("submission_write");
    expect(Object.keys(frame).sort()).toEqual(["ciphertext", "intake_key_id", "submission_id", "type"]);
  });

  it("reports STORED on a fresh write", async () => {
    const s = signalingThatReplies({ type: "submission_write_result", submission_id: SUBMISSION.submissionId, stored: true });
    const res = await send(s);
    expect(res).toMatchObject({ ok: true, stored: true, submissionId: SUBMISSION.submissionId });
  });

  it("distinguishes DUPLICATE from stored — never collapses it into plain success", async () => {
    // `stored: false` is usually the submitter's own retry, which is what makes retry-across-nodes
    // safe. It is ALSO the shape of a single-node censorship attack: submission_id is visible in the
    // clear to the receiving node, so a malicious operator can pre-insert garbage under the same id
    // at the other nodes and every retry resolves to "already present". Collapsing the two here
    // would destroy the information before anything could act on it.
    const s = signalingThatReplies({ type: "submission_write_result", submission_id: SUBMISSION.submissionId, stored: false });
    const res = await send(s);
    expect(res).toMatchObject({ ok: true, stored: false });
    expect(events.map((e) => e.event)).toContain("signal.submission.duplicate");
  });

  it("IGNORES a result for a DIFFERENT submission_id and still times out", async () => {
    // The inbound handler sees every frame on a shared stream. Accepting someone else's result would
    // report success for a submission that was never written.
    const s = signalingThatReplies({ type: "submission_write_result", submission_id: "cd".repeat(32), stored: true });
    const res = await send(s, 120);
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("submission_write_timeout");
  });
});

describe("DOD-END-SUBMIT-1 — failure modes that would otherwise be silent or misleading", () => {
  it("names the AMBIGUITY on a version-skew `not_authenticated` — never asserts one cause", async () => {
    // The trap (M10B-D25r F2): decodeInboundSignalingFrame returns null for an unknown frame kind and
    // the node replies not_authenticated. Reporting that verbatim is ERROR SUBSTITUTION — the label
    // names the exit point and sends the operator to the wrong subsystem. Directory nodes deploy
    // independently per region, so an upgraded daemon meeting an older node is the NORMAL rollout
    // case, not an edge.
    const s = signalingThatReplies({ type: "not_authenticated" });
    const res = await send(s);
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("submission_unsupported_by_node");
    expect(res.guidance).toMatch(/has not deployed|version/i);
    // It must NAME the other two producers rather than ruling them out. An earlier version asserted
    // "NOT an authentication problem", which is false when the frame really did arrive pre-auth.
    expect(res.guidance).toMatch(/authentication/i);
    expect(res.guidance).toMatch(/malformed/i);
  });

  it("reports the node's own refusal reason when it names one", async () => {
    const s = signalingThatReplies({ type: "submission_write_error", submission_id: SUBMISSION.submissionId, reason: "queue_full" });
    const res = await send(s);
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    // The upstream reason SURVIVES into the payload rather than being flattened (§5b).
    expect(res.guidance).toMatch(/queue_full/);
  });

  it("surfaces a send failure with the transport's reason, not a generic label", async () => {
    const s = signalingThatReplies(null, { ok: false as unknown as true, reason: "signaling_reconnecting" } as never);
    const res = await send(s);
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    // F7: the reason CODE is the transport's own cause, not the exit-point label.
    expect(res.reason).toBe("signaling_reconnecting");
    expect(res.guidance).toMatch(/signaling_reconnecting/);
    // F1: it must NOT claim a retry that no code performs.
    expect(res.guidance).toMatch(/NOT handed|nothing has retried/i);
  });

  it("TIMES OUT rather than hanging when the node never answers", async () => {
    // A submission is not complete until it is acknowledged. Hanging forever would leave the
    // operator with no result and no error — the exact silent-loss shape the return path exists to
    // close.
    const res = await send(signalingThatReplies(null), 100);
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("submission_write_timeout");
  });

  it("UNREGISTERS its inbound handler on EVERY terminal path — observed, not assumed", async () => {
    // The previous version of this test read the return value of registerInboundHandler and asserted
    // it was a function. That is true of any stub, and the test passed with `finally { unregister() }`
    // deleted — a hollow test named for a leak it could not see. This one counts the handlers.
    const ok = signalingThatReplies({ type: "submission_write_result", submission_id: SUBMISSION.submissionId, stored: true });
    await send(ok);
    expect(ok.handlers.length, "success path").toBe(0);

    const dup = signalingThatReplies({ type: "submission_write_result", submission_id: SUBMISSION.submissionId, stored: false });
    await send(dup);
    expect(dup.handlers.length, "duplicate path").toBe(0);

    const err = signalingThatReplies({ type: "submission_write_error", submission_id: SUBMISSION.submissionId, reason: "queue_full" });
    await send(err);
    expect(err.handlers.length, "node-error path").toBe(0);

    const timedOut = signalingThatReplies(null);
    await send(timedOut, 60);
    expect(timedOut.handlers.length, "timeout path").toBe(0);

    const unsent = signalingThatReplies(null, { ok: false as unknown as true, reason: "signaling_lost" } as never);
    await send(unsent);
    expect(unsent.handlers.length, "send-failure path").toBe(0);
  });
});
