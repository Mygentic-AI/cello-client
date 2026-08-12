/**
 * DOD-MP-CONTROL-N-1 — a control frame reaches EVERY current holder, derived from the chain.
 *
 * Found by the M14B live fleet smoke, not by any test: `close` and `kill` addressed
 * `doc.peerAgentId` — the single genesis counterparty frozen at creation — and returned after the
 * first send. In a mesh that is wrong twice over. With three holders only one was ever told. And
 * after a removal the genesis counterparty can BE the removed holder, so the frame went to the one
 * party it must not reach while the actual remaining co-author was never told at all — and the
 * operator was shown `peerNotified: true`.
 *
 * This is TIER2-READY lens 4 ("no frame assumes a single counterparty"), which the M14B DoD makes a
 * blocking invariant. The delivery target is the DERIVED participant set, exactly as FANOUT-1
 * established for update envelopes; control frames were simply never migrated to it.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { DocumentStore } from "../document-store.js";
import { createDocumentControlNotifier } from "../document-control-notifier.js";
import { decodeDocumentControl } from "@cello-protocol/protocol-types";
import type { Logger } from "../types.js";

const silent: Logger = {
  debug: () => {}, info: () => {}, warn: () => {}, error: () => {},
} as unknown as Logger;

const OWNER = "a".repeat(64);
const GENESIS_PEER = "b".repeat(64);
const JOINER = "c".repeat(64);
const DOC = "d".repeat(64);

interface Sent {
  peerAgentId: string;
  bytes: Uint8Array;
}

function fixture(opts: {
  holders?: { ok: true; holders: readonly string[] } | { ok: false; reason: string };
  sendFails?: ReadonlySet<string>;
  signThrows?: boolean;
} = {}) {
  const db = new DatabaseSync(":memory:");
  const store = new DocumentStore(db as never, silent);
  store.createDocument({
    documentId: DOC, ownerAgentId: OWNER, peerAgentId: GENESIS_PEER,
    documentType: "markdown", properties: {}, status: "active", createdAtMs: 1,
  });
  const sent: Sent[] = [];
  const warnings: Array<{ event: string; ctx: Record<string, unknown> }> = [];

  const notify = createDocumentControlNotifier({
    store,
    owners: () => [{ agentName: "me", ownerAgentId: OWNER }],
    holders: () => opts.holders ?? { ok: true, holders: [GENESIS_PEER, JOINER] },
    sign: async () => {
      if (opts.signThrows) throw new Error("key provider missing");
      return new Uint8Array(64).fill(7);
    },
    send: async (_agentName, input) => {
      sent.push({ peerAgentId: input.peerAgentId, bytes: input.bytes });
      return opts.sendFails?.has(input.peerAgentId)
        ? { ok: false as const, reason: "transport_unavailable" }
        : { ok: true as const };
    },
    now: () => 1_700_000_000_000,
    logger: { warn: (event, ctx) => warnings.push({ event, ctx }) },
  });

  return { notify, sent, warnings };
}

describe("control frames fan out to the DERIVED holder set", () => {
  it("tells EVERY current holder, not just the genesis counterparty", async () => {
    const f = fixture();
    const res = await f.notify(DOC, "close");

    expect(res.ok).toBe(true);
    // The defect in one assertion: this was 1 — the joiner, a full holder who had been converging
    // and publishing for the whole life of the document, was never told the document ended.
    expect(f.sent.map((s) => s.peerAgentId).sort()).toEqual([GENESIS_PEER, JOINER].sort());
    expect((res as { holdersNotified: Record<string, boolean> }).holdersNotified).toEqual({
      [GENESIS_PEER]: true,
      [JOINER]: true,
    });
  });

  it("does NOT address the genesis peer once the chain has removed them", async () => {
    // The live case that exposed this: A created with B, invited C, then removed B. `peerAgentId`
    // still says B. Sending there notifies the removed holder and nobody else.
    const f = fixture({ holders: { ok: true, holders: [JOINER] } });
    const res = await f.notify(DOC, "close");

    expect(res.ok).toBe(true);
    expect(f.sent.map((s) => s.peerAgentId)).toEqual([JOINER]);
    expect(f.sent.some((s) => s.peerAgentId === GENESIS_PEER)).toBe(false);
  });

  it("reports per holder — one unreachable holder neither blocks the others nor is papered over", async () => {
    const f = fixture({ sendFails: new Set([JOINER]) });
    const res = await f.notify(DOC, "close");

    // ok:true means "signed and attempted to every current holder". WHO took it is the map's job;
    // collapsing that to one boolean is how a partial fan-out reads as a clean one.
    expect(res.ok).toBe(true);
    expect((res as { holdersNotified: Record<string, boolean> }).holdersNotified).toEqual({
      [GENESIS_PEER]: true,
      [JOINER]: false,
    });
    // The reachable holder was still told — availability is not all-or-nothing.
    expect(f.sent.map((s) => s.peerAgentId)).toContain(GENESIS_PEER);
  });

  it("signs ONCE and sends the identical frame to each holder", async () => {
    const f = fixture();
    await f.notify(DOC, "kill");

    expect(f.sent).toHaveLength(2);
    const decoded = f.sent.map((s) => decodeDocumentControl(s.bytes));
    // A per-holder signature would be a per-holder TBS, and a control frame commits to the document
    // and the verb — not to a recipient. Re-signing per holder invites the two to diverge.
    expect(decoded[0]).toMatchObject({ verb: "kill", document_id: DOC, sender_agent_id: OWNER });
    expect(Buffer.from(f.sent[0]!.bytes)).toEqual(Buffer.from(f.sent[1]!.bytes));
  });

  it("REFUSES rather than falling back to the genesis peer when the chain cannot be derived", async () => {
    const f = fixture({ holders: { ok: false, reason: "document_chain_invalid" } });
    const res = await f.notify(DOC, "close");

    // The tempting fallback is the old behaviour — "we could not derive, so use peerAgentId". That
    // is precisely the bug this unit exists to remove, and after a removal it aims the frame at the
    // removed holder. A named refusal is the answer; the operator can act on it.
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_chain_invalid");
    expect(f.sent).toHaveLength(0);
  });

  it("a document with no remaining holders sends nothing and says so", async () => {
    const f = fixture({ holders: { ok: true, holders: [] } });
    const res = await f.notify(DOC, "close");

    // Reporting ok:true with an empty map would read as "everyone was told" to a caller that only
    // checks ok — the same collapse this unit refuses everywhere else.
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_no_holders");
    expect(f.sent).toHaveLength(0);
  });

  it("a signing failure is refused and named — before anything is sent", async () => {
    const f = fixture({ signThrows: true });
    const res = await f.notify(DOC, "close");

    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_control_unsigned");
    // Unchanged from the bilateral unit, and it must stay unchanged: an unsigned frame is rejected
    // at the far end, so sending N of them reports a fan-out that cannot land.
    expect(f.sent).toHaveLength(0);
    expect(f.warnings.map((w) => w.event)).toContain("document.control.unsigned");
  });

  it("still names document_unknown when no agent on this daemon holds it", async () => {
    const f = fixture();
    const res = await f.notify("e".repeat(64), "close");
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_unknown");
  });
});
