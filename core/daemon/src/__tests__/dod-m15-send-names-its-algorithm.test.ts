/**
 * THE OUTBOUND FRAME NAMES ITS ALGORITHM — `DOD-M15-SEALWIRE-1` bullet 6, part B2b.
 *
 * ─── Measured, not assumed: this file exists because a mutant survived ─────────────────────────
 *
 * After threading the algorithm through the send path, I deleted `content_hash_alg` from the
 * outbound frame and ran the daemon suite. **Green.** 2,700 tests and not one of them reads what the
 * sender actually puts on the wire.
 *
 * That is the same gap two reviews caught in earlier units of this story — the wiring is present and
 * nothing pins it — and it is the one that matters most here, because the receiving half (part B1)
 * is already built and already verifies under whatever the frame names. A sender that stops naming
 * it does not fail loudly; it silently reverts every peer to assuming `sha256`, which is correct
 * today and wrong the moment part B2b-2 starts salting.
 *
 * ─── The two properties, and why the second is not paranoia ────────────────────────────────────
 *
 *   1. The frame CARRIES the name.
 *   2. The name MATCHES the hash beside it.
 *
 * (2) is the failure mode that has no floor. A hash computed one way and labelled another is refused
 * by every peer, including a completely correct one — and the refusal looks like tampering, because
 * `content_hash_mismatch` is what a receiver reports when the bytes do not match the claim. There is
 * no partial degradation: every message fails, and the log accuses the sender.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, FakeNode, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { CelloNode } from "@cello-protocol/transport";
import { decode } from "cbor-x";
import { CONTENT_HASH_ALGS, contentHashFor } from "../wire-content-hash.js";
import { LEAF_KIND_MSG } from "../session-relay-client.js";

const SID = "7a".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const CONTENT = new TextEncoder().encode("the answer is 4200");
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Every frame the daemon actually wrote to the wire, decoded. */
function sentFrames(node: CelloNode | null): Array<Record<string, unknown>> {
  const raw = (node as unknown as { sent?: Uint8Array[] } | null)?.sent ?? [];
  return raw.flatMap((framed) => {
    for (let off = 0; off < Math.min(4, framed.length); off++) {
      try { return [decode(framed.subarray(off)) as Record<string, unknown>]; } catch { /* varint prefix */ }
    }
    return [];
  });
}

describe("DOD-M15-SEALWIRE-1 part B2b: what the sender puts on the wire", () => {
  let fx: TwoConnectionFixture | null = null;
  let node: CelloNode | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; node = null; });

  it("★ a content frame CARRIES content_hash_alg — the mutant that survived until this test", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-b2b-alg-", node: node = new FakeNode() as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, CONTENT);
    await fx.snm.sendContent("alice", SID, CONTENT, hash, "corr", LEAF_KIND_MSG, alg);
    await wait(200);

    const frame = sentFrames(node).find((f) => f["type"] === "content_frame");
    expect(frame, "the send must actually reach the wire for this to prove anything").toBeDefined();
    expect(
      frame!["content_hash_alg"],
      "without the name every peer falls back to assuming sha256 — correct today, wrong the moment we salt",
    ).toBe(CONTENT_HASH_ALGS.SHA256);
  }, 60_000);

  it("★ the NAME matches the HASH beside it — derived independently, not compared to itself", async () => {
    /**
     * The assertion with no floor if it breaks. Recomputing the hash here under the algorithm the
     * frame NAMES is the counterparty's own check: if the two disagree, every message is refused as
     * `content_hash_mismatch`, which reads as tampering rather than as a mislabel.
     *
     * Deliberately NOT `expect(frame.content_hash).toBe(hash)` — that compares the daemon against
     * the value this test handed it, which is satisfied by any consistent pair including a wrong one.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-b2b-match-", node: node = new FakeNode() as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, CONTENT);
    await fx.snm.sendContent("alice", SID, CONTENT, hash, "corr", LEAF_KIND_MSG, alg);
    await wait(200);

    const frame = sentFrames(node).find((f) => f["type"] === "content_frame")!;
    const declared = frame["content_hash_alg"] as string;
    const onWire = frame["content_hash"] as Uint8Array;
    const bytes = frame["content_bytes"] as Uint8Array;

    // The receiver's computation, done here from the frame alone — no access to what the sender chose.
    const recomputed = contentHashFor(bytes, { alg: declared, salt: null });
    expect(
      Buffer.from(recomputed).toString("hex"),
      "the hash on the wire must be reproducible under the algorithm the frame names, or every peer refuses it",
    ).toBe(Buffer.from(onWire).toString("hex"));
  }, 60_000);

  it("★ the decision point returns a hash and a label that AGREE", async () => {
    /**
     * One level below the wire: `contentHashForSession` exists so four send sites cannot each decide
     * separately. If it can return a mismatched pair, centralising it bought nothing — it would just
     * make every site wrong the same way.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-b2b-pair-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, CONTENT);
    expect(Buffer.from(hash).toString("hex"))
      .toBe(Buffer.from(contentHashFor(CONTENT, { alg, salt: null })).toString("hex"));
  }, 60_000);

  /**
   * ⚠️ THE DOCUMENT-ADAPTER ASSERTION LIVES IN `document-leaf-kind-on-the-wire.test.ts`, NOT HERE.
   *
   * B2b-1 first put a clone of it in this file — same regex, same two assertions — and review F5
   * called that correctly: a rename of the adapter would then break two tests, and someone fixes
   * one. It is merged into the original, which now checks BOTH trailing parameters and uses
   * `matchAll` so a second adapter appearing earlier in the file cannot silently become the thing
   * being guarded.
   *
   * The clone's stated justification had also gone stale. It said a lower-arity adapter "drops the
   * last argument with no error anywhere" — true when `sendContent`'s parameters were optional, and
   * false once they were required, because the inner call then has too few arguments. What survives
   * is the HARDCODE mutant (`..., leafKind, "sha256")`), which does compile, and that is what the
   * merged assertion catches.
   */
});
