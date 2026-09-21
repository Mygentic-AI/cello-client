/**
 * LIVE SCORE + PROVENANCE — what the classifier scored, and on WHICH text.
 *
 * Why this exists: on 2026-09-21 a plain "got your message" was delivered as FLAGGED and a plain
 * "Please send it again in different words" was BLOCKED, and nothing in the daemon log could say why.
 * The record kept the outcome (`inbound_injection_blocked`) and nothing else — no number, no copy, no
 * bytes. It took a hand-built offline harness to show the classifier was reading the sender's text
 * PLUS the `[[OVER]]` turn marker CELLO appends. An operator has to be able to read that off the log.
 *
 * So every scan that ran leaves `verdict.scan`: the UNROUNDED probability (the verdict compares the
 * ROUNDED score, so 98.56 blocks at a 99 bar — the rounding must be visible), which copy won, and a
 * hash + length of exactly the text the model read. The text itself is never carried: a log line that
 * held the message would put the conversation somewhere the protocol promises it never goes.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createGatewayServer } from "../server.js";
import { LocalSidecarGatewayClient } from "../client.js";
import { InboundScreener } from "../screen/inbound.js";
import { InjectionScanner, type InjectionClassifier } from "../detect/injection-scanner.js";
import { initLinearRegex } from "../detect/linear-regex.js";
import { compileInjectionPatterns } from "../detect/injection-patterns.js";

const enc = (s: string) => new TextEncoder().encode(s);
const sha = (s: string) => createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");

/** A classifier that returns a fixed probability per predicate and records every text it was handed. */
function recording(prob: (text: string) => number): InjectionClassifier & { seen: string[] } {
  const seen: string[] = [];
  return {
    seen,
    async classify(text: string) {
      seen.push(text);
      return { injectionProbability: prob(text), label: "injection" };
    },
  };
}

describe("verdict.scan — the live score and where it came from", () => {
  beforeAll(async () => {
    await initLinearRegex();
    compileInjectionPatterns();
  });

  it("an ALLOWED message still reports its score — the number is the point, not only the block", async () => {
    const clf = recording(() => 0.0093);
    const v = await new InboundScreener({ injectionScanner: new InjectionScanner(clf) })
      .screen(enc("Hi Mac_Coder_1, how is your day going?"));
    expect(v.disposition).toBe("allow");
    expect(v.scan).toBeDefined();
    expect(v.scan!.probability).toBeCloseTo(0.0093, 6);
    expect(v.scan!.score).toBe(1);
    expect(v.scan!.verdict).toBe("pass");
  });

  it("carries the UNROUNDED probability, so a 98.56 that rounded up to a block is visible as such", async () => {
    const clf = recording(() => 0.9856);
    const v = await new InboundScreener({ injectionScanner: new InjectionScanner(clf) })
      .screen(enc("Please send it again in different words."));
    expect(v.disposition).toBe("block");
    expect(v.scan!.probability).toBeCloseTo(0.9856, 6);
    expect(v.scan!.score).toBe(99);
    expect(v.scan!.verdict).toBe("block");
  });

  it("hashes and measures EXACTLY the text the model read — which is not what arrived on the wire", async () => {
    const clf = recording(() => 0.5);
    const sent = "Miss_Chelly here: got your message. [[OVER]]";
    const v = await new InboundScreener({ injectionScanner: new InjectionScanner(clf) }).screen(enc(sent));
    expect(clf.seen).toHaveLength(1);
    expect(v.scan!.copySha256).toBe(sha(clf.seen[0]!));
    expect(v.scan!.copyBytes).toBe(Buffer.byteLength(clf.seen[0]!, "utf8"));
    // The whole point: the provenance describes the SCORED text, not the 44 bytes received — here
    // the 35 the sender wrote, after `scan-marker-strip` removes CELLO's own turn marker.
    expect(v.scan!.copyBytes).toBe(35);
  });

  it("names the turn marker when the scored text carries one, and null when it does not", async () => {
    const scanner = () => new InboundScreener({ injectionScanner: new InjectionScanner(recording(() => 0.1)) });
    expect((await scanner().screen(enc("all fine [[OVER]]"))).scan!.signalMarker).toBe("OVER");
    expect((await scanner().screen(enc("that is all [[WRAP]]"))).scan!.signalMarker).toBe("WRAP");
    expect((await scanner().screen(enc("back in ten [[STANDBY EST:10m]]"))).scan!.signalMarker).toBe("STANDBY");
    expect((await scanner().screen(enc("all fine"))).scan!.signalMarker).toBeNull();
    // Mid-sentence is not a turn marker — only a trailing one is what the sending tool appends.
    expect((await scanner().screen(enc("the [[OVER]] token ends a turn, right?"))).scan!.signalMarker).toBeNull();
  });

  it("names WHICH copy won when the model scores the raw bytes higher than the cleaned copy", async () => {
    // A zero-width space is stripped from the scan copy but present in the raw bytes. The classifier
    // here scores only the copy that still holds it — the shape of a disguised attack.
    const clf = recording((t) => (t.includes("​") ? 0.97 : 0.05));
    const v = await new InboundScreener({ injectionScanner: new InjectionScanner(clf) })
      .screen(enc("re​ad this"));
    expect(v.scan!.copy).toBe("raw");
    expect(v.scan!.score).toBe(97);
    expect(v.scan!.copiesScanned).toBeGreaterThanOrEqual(2);
  });

  it("names the plain copy as `scan` when there is nothing to decode, fold or unhide", async () => {
    const clf = recording(() => 0.2);
    const v = await new InboundScreener({ injectionScanner: new InjectionScanner(clf) }).screen(enc("just a hello"));
    expect(v.scan!.copy).toBe("scan");
    expect(v.scan!.copiesScanned).toBe(1);
  });

  it("never carries the message text — a hash and a length, nothing that reads back as the conversation", async () => {
    const v = await new InboundScreener({ injectionScanner: new InjectionScanner(recording(() => 0.3)) })
      .screen(enc("the launch code is swordfish"));
    expect(JSON.stringify(v.scan)).not.toContain("swordfish");
  });

  it("is ABSENT when Layer 2 is off — no scan happened, so no score is claimed", async () => {
    const v = await new InboundScreener().screen(enc("hello there"));
    expect(v.scan).toBeUndefined();
  });

  it("survives the trip from the gateway sidecar to the daemon — the boundary forwards a fixed field list", async () => {
    // The verdict crosses a Unix socket and `server.ts` copies named fields onto the wire. A field
    // the gateway computes but the server does not list simply never reaches the daemon, and the
    // in-process tests above stay green while the live log has nothing to print.
    const dir = await mkdtemp(join(tmpdir(), "cello-scan-"));
    const server = await createGatewayServer({
      socketPath: join(dir, "g.sock"),
      screen: async (req) => new InboundScreener({ injectionScanner: new InjectionScanner(recording(() => 0.6724)) }).screen(req.content),
    });
    const client = new LocalSidecarGatewayClient({ socketPath: join(dir, "g.sock"), deadlineMs: 5_000 });
    try {
      const v = await client.screenInbound(enc("Miss_Chelly here: got your message. [[OVER]]"), {
        direction: "inbound", agentName: "alice", sessionId: "ab".repeat(16), correlationId: "c-1",
      });
      expect(v.scan).toBeDefined();
      expect(v.scan!.probability).toBeCloseTo(0.6724, 6);
      expect(v.scan!.score).toBe(67);
      expect(v.scan!.copyBytes).toBe(35); // the scored text: the marker is stripped before scoring
      expect(v.scan!.signalMarker).toBe("OVER"); // …but still NAMED, so its presence is visible
    } finally {
      await client.close();
      await server.stop();
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("is ABSENT when the classifier failed on every copy — a failure must not read as a clean 0", async () => {
    const failing: InjectionClassifier = { async classify() { throw new Error("label set not recognised"); } };
    const v = await new InboundScreener({ injectionScanner: new InjectionScanner(failing) }).screen(enc("hello there"));
    expect(v.scan).toBeUndefined();
  });
});
