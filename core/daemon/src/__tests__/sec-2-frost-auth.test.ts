/**
 * SEC-2 (client side): the NetworkDirectoryNode must attach a K_local auth signature to every
 * /cello/frost/1.0.0 commit/sign request, bound to (agentPubkey, epochId, tail) — tail = utf8("commit")
 * for a commit, the framedMsg for a sign. The directory verifies exactly this (verifyFrostAuth); without
 * it the signing stream is a blind oracle (the forgery hole). These tests capture the frame the client
 * sends and assert the authSig verifies over the correct binding — and that a DIFFERENT framedMsg does
 * NOT verify (the binding has teeth), and that with no signer threaded the field is absent.
 */
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { Encoder, decode as cborDecode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { generateKeypair, verify } from "@cello-protocol/crypto";
import { NetworkDirectoryNode } from "../network-directory-node.js";

const CBOR = new Encoder({ tagUint8Array: false });

const FROST_AUTH_DOMAIN = "CELLO-FROST-AUTH-v1";
function frostAuthHash(agentPubkeyHex: string, epochId: string, tail: Uint8Array): Uint8Array {
  return new Uint8Array(
    createHash("sha256")
      .update(Buffer.concat([
        Buffer.from(FROST_AUTH_DOMAIN, "utf8"),
        Buffer.from(agentPubkeyHex, "hex"),
        Buffer.from(epochId, "utf8"),
        Buffer.from(tail),
      ]))
      .digest(),
  );
}
// SEC-2 domain separation: 0x00 = commit; 0x01 || framedMsg = sign.
const COMMIT_TAIL = new Uint8Array([0x00]);
function signTail(framedMsg: Uint8Array): Uint8Array {
  return Buffer.concat([Buffer.from([0x01]), Buffer.from(framedMsg)]);
}

// A fake CelloNode whose newStream returns a capturing stream: it records the request bytes the client
// sends, and yields a canned (lp-encoded) response so generateCommitment/signRound complete without error.
function makeCapturingNode(responseFrame: Record<string, unknown>) {
  const captured: Array<{ subarray(): Uint8Array }> = [];
  const respBytes = (lp.encode.single(CBOR.encode(responseFrame)) as { subarray(): Uint8Array }).subarray();
  const stream = {
    send(data: { subarray(): Uint8Array }) { captured.push(data); },
    close: async () => {},
    abort() {},
    status: "open",
    async *[Symbol.asyncIterator]() { yield respBytes; },
  };
  const node = {
    getPeerId: () => "12D3KooWFakePeerForSec2Test",
    newStream: async () => stream,
    dial: async () => ({ peerId: "remote" }),
  };
  return { node: node as never, captured };
}

async function decodeSentFrame(captured: Array<{ subarray(): Uint8Array }>): Promise<Record<string, unknown>> {
  const bytes = captured[0].subarray();
  const src = (async function* () { yield bytes; })();
  for await (const msg of lp.decode(src)) {
    const b = msg instanceof Uint8Array ? msg : (msg as { subarray(): Uint8Array }).subarray();
    return cborDecode(b) as Record<string, unknown>;
  }
  throw new Error("no frame captured");
}

describe("SEC-2 client: NetworkDirectoryNode attaches a valid K_local authSig", () => {
  it("commit request carries an authSig that verifies over (pubkey, epoch, 'commit')", async () => {
    const kp = generateKeypair();
    const pubkeyHex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const epochId = `${pubkeyHex}:epoch:1`;
    const { node, captured } = makeCapturingNode({
      type: "frost_commit_response", ok: true, nodeId: "nodeA", nonceCommitment: { hiding: new Uint8Array([1]), binding: new Uint8Array([2]) },
    });
    const stub = new NetworkDirectoryNode({ id: "nodeA", node, directoryPeerId: "peerA", directoryMultiaddrs: ["/ip4/127.0.0.1/tcp/1"] });
    stub.setBootstrapContext(pubkeyHex, epochId, (h) => kp.sign(h));

    await stub.generateCommitment();
    const frame = await decodeSentFrame(captured);

    expect(frame.type).toBe("frost_commit_request");
    const authSig = frame.authSig as Uint8Array;
    expect(authSig, "commit frame must carry an authSig").toBeInstanceOf(Uint8Array);
    const pubkey = Uint8Array.from(Buffer.from(pubkeyHex, "hex"));
    expect(verify(pubkey, frostAuthHash(pubkeyHex, epochId, COMMIT_TAIL), authSig)).toBe(true);
  });

  it("sign request's authSig is BOUND to the framedMsg — verifies over it, and NOT over a different msg", async () => {
    const kp = generateKeypair();
    const pubkeyHex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const epochId = `${pubkeyHex}:epoch:1`;
    const { node, captured } = makeCapturingNode({ type: "frost_sign_response", ok: true, partialSignature: new Uint8Array([9, 9]) });
    const stub = new NetworkDirectoryNode({ id: "nodeA", node, directoryPeerId: "peerA", directoryMultiaddrs: ["/ip4/127.0.0.1/tcp/1"] });
    stub.setBootstrapContext(pubkeyHex, epochId, (h) => kp.sign(h));

    const framedMsg = new Uint8Array([42, 43, 44, 45]);
    await stub.signRound({ msg: framedMsg, commitmentList: [], ceremonyId: "cer-1" } as never);
    const frame = await decodeSentFrame(captured);

    expect(frame.type).toBe("frost_sign_request");
    const authSig = frame.authSig as Uint8Array;
    expect(authSig).toBeInstanceOf(Uint8Array);
    const pubkey = Uint8Array.from(Buffer.from(pubkeyHex, "hex"));
    // Verifies over the ACTUAL framedMsg (with the sign-frame prefix)…
    expect(verify(pubkey, frostAuthHash(pubkeyHex, epochId, signTail(framedMsg)), authSig)).toBe(true);
    // …but NOT over a different framedMsg — the binding is what defeats forging an arbitrary message.
    expect(verify(pubkey, frostAuthHash(pubkeyHex, epochId, signTail(new Uint8Array([1, 2, 3, 4]))), authSig)).toBe(false);
    // …and NOT over the commit tail — commit and sign are domain-separated.
    expect(verify(pubkey, frostAuthHash(pubkeyHex, epochId, COMMIT_TAIL), authSig)).toBe(false);
  });

  it("with NO signer threaded, the frame omits authSig (an enforcing directory then refuses AUTH_REQUIRED)", async () => {
    const kp = generateKeypair();
    const pubkeyHex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const epochId = `${pubkeyHex}:epoch:1`;
    const { node, captured } = makeCapturingNode({
      type: "frost_commit_response", ok: true, nodeId: "nodeA", nonceCommitment: { hiding: new Uint8Array([1]), binding: new Uint8Array([2]) },
    });
    const stub = new NetworkDirectoryNode({ id: "nodeA", node, directoryPeerId: "peerA", directoryMultiaddrs: ["/ip4/127.0.0.1/tcp/1"] });
    stub.setBootstrapContext(pubkeyHex, epochId); // no signAuth

    await stub.generateCommitment();
    const frame = await decodeSentFrame(captured);
    expect(frame.authSig).toBeUndefined();
  });
});
