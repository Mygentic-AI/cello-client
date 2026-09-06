/**
 * THE DAEMON ANNOUNCES ITS SALT STATE WHEN THE COUNTERPARTY CONNECTS — `DOD-M15-SEALWIRE-1`
 * bullet 6, part A, the OUTBOUND half.
 *
 * ─── Why this file exists, and it is the answer to a measured gap ──────────────────────────────
 *
 * `dod-m15-salt-agreement-wired.test.ts` drives the real inbound handler, so it catches a deleted
 * dispatch branch and a salt that never reaches disk. It caught neither of these, measured with
 * running mutants:
 *
 *   remove `void this.#sendSaltFrame(...)` from the counterparty-connect handler  → ALL GREEN
 *   mint a FRESH contribution on every call instead of once per session           → ALL GREEN
 *
 * Both are total failures of the feature. Without the announcement, two daemons that each wait for
 * the other say nothing and no salt is ever agreed. With a per-call contribution, the two sides keep
 * deriving against a moving value, the fingerprints never settle, and the symptom — a session that
 * reconnects and still disagrees — reads as a network fault rather than a bug.
 *
 * Neither is reachable from the inbound seam, because both live on the path a REAL peer connection
 * drives. So this file stands up a real second libp2p node, dials the session node, and reads what
 * comes back over `/cello/content/1.0.0` — which also makes it the only place that can check the
 * one property the channel rule is about: what actually goes on the wire.
 */

import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createNode, CELLO_CONTENT_PROTOCOL_ID, type CelloNode } from "@cello-protocol/transport";
import {
  generateKeypair, deriveSessionSalt, saltFingerprint,
  SALT_CONTRIBUTION_BYTES, SALT_FINGERPRINT_BYTES,
} from "@cello-protocol/crypto";
import { decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "cd".repeat(32);
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitUntil(fn: () => boolean, timeoutMs: number, everyMs = 50): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return true;
    await wait(everyMs);
  }
  return fn();
}

/** Frames the counterparty node received on the content protocol, decoded. */
type Received = Record<string, unknown>;

/**
 * A multiaddr the counterparty can actually dial — the addressed one, with the `/p2p/` component.
 *
 * Dialling an address without it fails as *"no valid addresses for peer: unknown peer"*, which names
 * the dial and says nothing about the missing identity, so the fallback appends the peer id rather
 * than letting that message be the diagnosis.
 */
function dialableAddr(fx: TwoConnectionFixture, created: { ok: boolean }): string {
  const addrs = (created as { addrs?: string[] }).addrs ?? [];
  const addressed = addrs.find((a) => a.includes("/p2p/"));
  if (addressed) return addressed;
  const peerId = fx.snm.getSessionNodePeerId("alice", SID);
  const base = addrs.find((a) => a.includes("/tcp/") && !a.endsWith("/tcp/0"));
  if (!base || !peerId) throw new Error(`no dialable address: addrs=${JSON.stringify(addrs)} peerId=${peerId}`);
  return `${base}/p2p/${peerId}`;
}

/**
 * The fixture ships a `FakeNode` whose `onPeerConnect` is an empty method, so nothing it drives can
 * observe the connect handler at all — which is precisely why the two mutants above survived. This
 * hands it a REAL libp2p node instead, on the option the fixture already exposes for it.
 */
async function fixtureWithRealNode(prefix: string): Promise<{ fx: TwoConnectionFixture; node: CelloNode }> {
  const node = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
  const fx = await startTwoConnectionFixture({ dirPrefix: prefix, node });
  return { fx, node };
}

async function startCounterparty(inbox: Received[]): Promise<CelloNode> {
  const node = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
  await node.start();
  await node.handle(CELLO_CONTENT_PROTOCOL_ID, (stream) => {
    void (async () => {
      const iter = (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;
      const result = await iter.next();
      if (result.done || result.value === undefined) return;
      const raw = result.value;
      const bytes = raw instanceof Uint8Array ? raw
        : Buffer.isBuffer(raw) ? new Uint8Array(raw as Buffer)
        : (raw as { subarray(): Uint8Array }).subarray();
      inbox.push(decode(bytes) as Received);
    })();
  });
  return node;
}

describe("DOD-M15-SEALWIRE-1 part A: the announcement rides a real connection", () => {
  let fx: TwoConnectionFixture | null = null;
  let peer: CelloNode | null = null;
  let tempDir = "";

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-salt-announce-"));
    process.env["CELLO_LISTEN_ADDR"] = "/ip4/127.0.0.1/tcp/0";
  });
  afterEach(async () => {
    delete process.env["CELLO_LISTEN_ADDR"];
    if (peer) { try { await peer.stop(); } catch { /* already down */ } peer = null; }
    if (fx) { await fx.cleanup(); fx = null; }
    await rm(tempDir, { recursive: true, force: true });
  });

  it("★ the daemon offers its CONTRIBUTION the moment the counterparty connects", async () => {
    /**
     * The mutant this exists for: delete the call from the connect handler and nothing else in the
     * suite moves. Two daemons each waiting for the other agree nothing, forever.
     */
    const inbox: Received[] = [];
    peer = await startCounterparty(inbox);
    ({ fx } = await fixtureWithRealNode("cello-salt-ann-a-"));

    // The session must name the REAL dialer as its counterparty: the connect handler filters on
    // exactly that peer id, so a fixture's placeholder would be discarded as an unrelated peer —
    // and the test would pass for the wrong reason.
    const created = await fx.// The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
// session it cannot anchor, and a fixture builds one below the paths that record it.
snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
snm.createSessionNode(SID, "alice", "bobpubkeyhex", peer.getPeerId(), "salt-test");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    fx.snm.setSessionContentKeyForTest("alice", SID, new Uint8Array(32).fill(0x7e));
    expect(created.ok, "the session node must come up before anything can connect to it").toBe(true);
    const addr = dialableAddr(fx, created);
    await peer.dial(addr);
    expect(await waitUntil(() => inbox.length > 0, 10_000), "no salt frame arrived on the connection").toBe(true);

    const frame = inbox[0]!;
    expect(frame["type"]).toBe("session_salt_agreement");
    expect(frame["session_id"]).toBe(SID);
    const contribution = frame["contribution"];
    expect(contribution, "a daemon holding no salt must offer a contribution").toBeInstanceOf(Uint8Array);
    expect((contribution as Uint8Array).length).toBe(SALT_CONTRIBUTION_BYTES);
    expect(frame["fingerprint"], "and must not claim to hold one at the same time").toBeUndefined();
    // Not all-zero: the peer would refuse it, and refusing our own degenerate contribution is
    // exactly what `generateSaltContribution` exists to make impossible.
    expect((contribution as Uint8Array).some((b) => b !== 0)).toBe(true);
  }, 60_000);

  it("★ RECONNECTING re-offers the SAME contribution — the value is minted once per session", async () => {
    /**
     * The second mutant, and the subtler one. A contribution regenerated per announcement is
     * invisible to every module test, because each one is individually well-formed. It breaks the
     * exchange only across two announcements, which is exactly what a reconnect produces.
     */
    const inbox: Received[] = [];
    peer = await startCounterparty(inbox);
    ({ fx } = await fixtureWithRealNode("cello-salt-ann-b-"));

    const created = await fx.// The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
// session it cannot anchor, and a fixture builds one below the paths that record it.
snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
snm.createSessionNode(SID, "alice", "bobpubkeyhex", peer.getPeerId(), "salt-test");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    fx.snm.setSessionContentKeyForTest("alice", SID, new Uint8Array(32).fill(0x7e));
    const addr = dialableAddr(fx, created);

    /**
     * 007-CRYPTO: the SALT frames only. The signed ephemeral now rides the same content stream and
     * the same connect, so this inbox holds both kinds and "the last frame" is no longer the salt
     * one. Selecting by type keeps the test about the property it names — a contribution minted once
     * per session — instead of about which frame happened to arrive last.
     */
    const saltFrames = () => inbox.filter((f) => f["type"] === "session_salt_agreement");
    await peer.dial(addr);
    expect(await waitUntil(() => saltFrames().length >= 1, 10_000)).toBe(true);
    const first = saltFrames()[0]!["contribution"] as Uint8Array;

    // Drop the connection and come back, which is the ordinary shape of a session that outlives a
    // network blip — and the moment a per-call mint would diverge.
    await peer.hangUp(fx.snm.getSessionNodePeerId("alice", SID)!);
    await wait(300);
    await peer.dial(addr);
    expect(await waitUntil(() => saltFrames().length >= 2, 10_000), "the reconnect must re-announce").toBe(true);

    const second = saltFrames()[saltFrames().length - 1]!["contribution"] as Uint8Array;
    expect(Buffer.from(second).toString("hex"), "a fresh contribution per announcement never converges").toBe(
      Buffer.from(first).toString("hex"),
    );
  }, 60_000);

  it("★ once a salt is agreed the daemon announces a FINGERPRINT and stops offering a contribution", async () => {
    /**
     * The channel rule's observable half: what leaves this machine after agreement is a short
     * one-way digest, never the salt. A relay forwarding the stream sees ciphertext either way, but
     * the frame's own contents are the last line — and `SALT_FINGERPRINT_BYTES` being visibly
     * shorter than a salt is what stops anyone mistaking one for key material.
     */
    const inbox: Received[] = [];
    peer = await startCounterparty(inbox);
    ({ fx } = await fixtureWithRealNode("cello-salt-ann-c-"));

    const created = await fx.// The session's starting point, seeded BEFORE creation: `createSessionNode` refuses a
// session it cannot anchor, and a fixture builds one below the paths that record it.
snm.setSessionGenesisForTest("alice", SID, new Uint8Array(32).fill(0x9c));
snm.createSessionNode(SID, "alice", "bobpubkeyhex", peer.getPeerId(), "salt-test");
    // 007-CRYPTO: the state a completed key exchange leaves — a live send needs an agreed key.
    fx.snm.setSessionContentKeyForTest("alice", SID, new Uint8Array(32).fill(0x7e));
    const addr = dialableAddr(fx, created);
    await peer.dial(addr);
    expect(await waitUntil(() => inbox.length >= 1, 10_000)).toBe(true);

    // Answer with our own half over the real handler, so the daemon derives and stores a salt.
    const ours = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x3d);
    await fx.snm.handleContentFrameForTest(
      "alice", SID,
      lp.encode.single(Buffer.from(
        (await import("@cello-protocol/protocol-types")).encodeCbor({
          type: "session_salt_agreement", session_id: SID, contribution: ours,
        }) as Uint8Array,
      )).subarray(),
      peer.getPeerId(),
    );
    expect(await waitUntil(() => fx!.eventsNamed("session.salt.agreed").length > 0, 10_000)).toBe(true);

    // The derive path announces immediately; that frame is the one to inspect.
    expect(await waitUntil(() => inbox.some((f) => f["fingerprint"] !== undefined), 10_000)).toBe(true);
    const announced = inbox.filter((f) => f["fingerprint"] !== undefined).pop()!;
    expect(announced["contribution"], "a side that holds a salt must not re-offer a contribution").toBeUndefined();
    const fingerprint = announced["fingerprint"] as Uint8Array;
    expect(fingerprint.length).toBe(SALT_FINGERPRINT_BYTES);
    expect(fingerprint.length).toBeLessThan(SALT_CONTRIBUTION_BYTES);

    /**
     * ★ THE SINGLE MOST IMPORTANT ASSERTION IN THE UNIT, and until review F2 it did not exist.
     *
     * The wired file checked the stored salt by sending back a fingerprint DERIVED FROM THE ROW —
     * so both sides of that comparison came from the same row, and the daemon could have stored 32
     * random bytes and still answered `fingerprint_match`. It proved self-consistency, which any
     * bytes satisfy. The one property the whole feature exists for — that the two daemons compute
     * the SAME value — was untested.
     *
     * This is the counterparty's actual computation, done here independently: we hold both halves
     * (theirs came off the wire, ours we chose), so we can derive the salt ourselves and check that
     * what the daemon published is a digest of THAT. A daemon storing anything else fails here.
     */
    const theirHalf = inbox[0]!["contribution"] as Uint8Array;
    expect(Buffer.from(fingerprint).toString("hex")).toBe(
      Buffer.from(saltFingerprint(deriveSessionSalt(theirHalf, ours))).toString("hex"),
    );
  }, 60_000);
});
