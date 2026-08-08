/**
 * DOD-DOC-LEAF-1 (client half) — a document leaf must SAY it is a document leaf ON THE WIRE.
 *
 * ── THE DEFECT THIS PINS ─────────────────────────────────────────────────────────────────────────
 *
 * The daemon appends its OWN copy of a document leaf with kind `doc` (daemon.ts wires `appendLeaf`
 * to `appendSessionLeaf(..., "doc", ...)`). But the copy it submits to the RELAY went through
 * `submitMessageHash`, which hardcodes `LEAF_KIND_MSG`. So every document update was witnessed as
 * a MESSAGE, and `LEAF_KIND_DOC` had no production caller at all — only a test asserting its value.
 *
 * ── WHAT THAT COSTS, AND WHY IT IS NOT COSMETIC ──────────────────────────────────────────────────
 *
 * The seal certificate is computed by the DIRECTORY from the leaves the RELAY witnessed, not from
 * the sender's local tree. `seal-legibility.ts` deliberately excludes `doc`/`reject` leaves from
 * two computations, and says why:
 *
 *   - `answered` — "A document update is applied MECHANICALLY by the peer's daemon with no agent
 *     involved, so counting one as a reply would let a peer's daemon satisfy the unanswered-tail
 *     check on its operator's behalf — the exact property `answered` exists to expose."
 *   - `final_message` — a document update must not be reported as the last thing someone SAID.
 *
 * Both guards test `leaf.kind === "doc" || leaf.kind === "reject"`. With every document leaf
 * arriving as `msg`, NEITHER GUARD COULD EVER FIRE. Measured on live cross-machine traffic
 * 2026-08-08: a session carrying two document leaves and zero messages sealed with a receipt
 * naming a document update as `final_message`.
 *
 * The server half has been ready since 2026-08-04 — the relay admits 0x04/0x05 and hashes each in
 * its own domain (`RELAY_LEAF_KINDS`, `RELAY_LEAF_HASHERS`), and the deployed build carries it.
 * Only the client never said the word.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { LEAF_KIND_MSG, LEAF_KIND_CTRL, LEAF_KIND_DOC, LEAF_KIND_REJECT } from "../session-relay-client.js";
import { createDocumentDeliveryTransport } from "../document-delivery-transport.js";
import type { Logger } from "../types.js";

function silentLogger(): Logger {
  const noop = () => {};
  const l = { debug: noop, info: noop, warn: noop, error: noop, child: () => l } as unknown as Logger;
  return l;
}

describe("a document leaf is witnessed as a DOCUMENT, not as a message", () => {
  it("the delivery path asks for LEAF_KIND_DOC when it submits to the relay", async () => {
    // The whole claim in one observation: what leaf kind does the document path hand to
    // `sendContent`? Asserted at the transport boundary rather than by reading the relay frame,
    // because that boundary is the one place a future caller could silently drop it again.
    const submitted: Array<number | undefined> = [];

    const deps = {
      agentName: "A",
      logger: silentLogger(),
      appendLeaf: () => {},
      lookupPeer: async () => ({ ok: true, online: true }) as never,
      sealSession: async () => {},
      activeSessionsWith: () => ["session-1"],
      openSession: async () => ({ ok: true, sessionId: "session-1" }) as never,
      encodeEnvelope: () => ({ bytes: new Uint8Array([1, 2, 3]), hash: new Uint8Array(32).fill(9) }),
      awaitAck: async () => true,
      drainHeld: async () => {},
      sendContent: async (
        _agent: string,
        _sessionId: string,
        _content: Uint8Array,
        _hash: Uint8Array,
        _correlationId: string,
        leafKind?: number,
      ) => {
        submitted.push(leafKind);
        return { ok: true as const, delivered: true as const };
      },
    };

    const transport = createDocumentDeliveryTransport(deps as never);
    await transport.deliver({
      peerAgentId: "p".repeat(64),
      documentId: "d".repeat(64),
      envelope: { envelopeHash: "e".repeat(64) } as never,
      correlationId: "corr-1",
    });

    expect(submitted.length, "the document was never sent, so this test proves nothing").toBeGreaterThan(0);
    expect(
      submitted[0],
      "a document update was witnessed as a MESSAGE — the directory's doc/reject guards cannot fire",
    ).toBe(LEAF_KIND_DOC);
  });

  it("every HOP forwards it — the composition root dropped it and nothing complained", () => {
    // THE SECOND HALF OF THE SAME DEFECT, and the reason the first fix shipped without working.
    //
    // The transport asked for 0x04 correctly. daemon.ts's adapter was written
    //   `(agent, sessionId, content, contentHash, correlationId) => manager.sendContent(...)`
    // — five parameters where the dep declares six. TypeScript accepts that silently: a function of
    // LOWER arity is assignable to one of higher arity. So the argument was discarded one hop below
    // the boundary the test above asserts, and the wire was unchanged on live traffic.
    //
    // Asserted structurally, on the SOURCE of the composition root, because that is the only thing
    // that fails when someone re-writes the adapter with the shorter signature. A behavioural test
    // here would have to stand up the whole daemon, and a mock of this seam is precisely what hid
    // the defect the first time.
    const root = readFileSync(new URL("../daemon.ts", import.meta.url), "utf8");

    const contentAdapter = /sendContent:\s*\(([^)]*)\)\s*=>\s*\n?\s*sessionNodeManager\.sendContent\(([^)]*)\)/.exec(root);
    expect(contentAdapter, "the sendContent adapter in daemon.ts was renamed or restructured").not.toBeNull();
    expect(
      contentAdapter![1].includes("leafKind"),
      "daemon.ts's sendContent adapter does not ACCEPT leafKind — the transport's 0x04 is dropped here",
    ).toBe(true);
    expect(
      contentAdapter![2].includes("leafKind"),
      "daemon.ts's sendContent adapter accepts leafKind but does not PASS it on",
    ).toBe(true);

    const frameAdapter = /sendFrame:\s*async\s*\(([^)]*)\)/.exec(root);
    expect(frameAdapter, "the sendFrame adapter in daemon.ts was renamed or restructured").not.toBeNull();
    expect(
      frameAdapter![1].includes("leafKind"),
      "daemon.ts's sendFrame adapter drops leafKind, so a refusal cannot be witnessed as 0x05",
    ).toBe(true);
  });

  it("the four leaf kinds stay distinct, because the guards discriminate on them", () => {
    // Kept from the original constant test, which was the ONLY reference to LEAF_KIND_DOC in the
    // repository. A constant asserted by a test and used by no caller reads exactly like a wired
    // feature; that is how this went unnoticed.
    expect(new Set([LEAF_KIND_MSG, LEAF_KIND_CTRL, LEAF_KIND_DOC, LEAF_KIND_REJECT]).size).toBe(4);
    expect(LEAF_KIND_DOC).toBe(0x04);
    expect(LEAF_KIND_REJECT).toBe(0x05);
  });
});
