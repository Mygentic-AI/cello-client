/**
 * 081-RELAYFREE — **THE REAL `relayAbandon` WIRE METHOD, driven against a stub stream.**
 *
 * The close-handler tests (C1/C2/cap/no-slot) mock the whole `AgentRelayClient`, so the real
 * `relayAbandon` — the frame it encodes, the `session_abandon_ok`/`session_abandon_refused` dispatch,
 * the `#pendingAbandon` slot and the ack-timeout race — never runs there. This file exercises exactly
 * that, the same way `dod-m15-awayscope-1-concurrent-queries.test.ts` drives the real `queryLiveness`:
 * a live stream installed for the client to send on, and dispatched frames the reader consumes.
 */
import { describe, it, expect, vi } from "vitest";
import { decode } from "cbor-x";
import { AgentRelayClient } from "../session-relay-client.js";
import { generateKeypair } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";
import type { Stream } from "@libp2p/interface";

const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const SID = new Uint8Array(16).fill(0x5f);

/**
 * relayAbandon awaits `#ensureConnected` before it sends the frame and installs `#pendingAbandon`, so
 * a dispatched ack must wait for that to happen — dispatching synchronously would find no resolver and
 * be dropped. One macrotask flush is enough (the connect check resolves immediately with a live stream).
 */
const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

function installStream(client: AgentRelayClient): Uint8Array[] {
  const sent: Uint8Array[] = [];
  client.installStreamForTest({
    send(b: { subarray?: () => Uint8Array } | Uint8Array) {
      sent.push(b instanceof Uint8Array ? b : (b as { subarray(): Uint8Array }).subarray());
    },
    async close() {}, abort() {}, status: "open",
  } as unknown as Stream);
  return sent;
}

/**
 * Un-frame the last frame the client sent. `installStream` captures the `lp.encode.single(cbor)`
 * bytes, which are a single unsigned-varint length followed by the CBOR body — strip the prefix and
 * decode the body.
 */
function lastFrame(sent: Uint8Array[]): Record<string, unknown> {
  const bytes = sent[sent.length - 1]!;
  let i = 0, shift = 0, len = 0;
  for (;;) {
    const b = bytes[i++]!;
    len |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
  }
  return decode(bytes.subarray(i, i + len)) as Record<string, unknown>;
}

async function makeClient(): Promise<AgentRelayClient> {
  const kp = await generateKeypair();
  return new AgentRelayClient({
    relayPeerId: "12D3KooWFakeRelayForAbandon",
    relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/fake"],
    keyProvider: { getPublicKey: async () => kp.publicKey, sign: async (m: Uint8Array) => kp.sign(m) } as never,
    senderPubkey: kp.publicKey,
    logger: noopLogger,
  });
}

describe("081-RELAYFREE: AgentRelayClient.relayAbandon over a stub stream", () => {
  it("★★★ encodes a session_abandon frame naming the session, and the ok ack resolves released", async () => {
    const client = await makeClient();
    const sent = installStream(client);

    const p = client.relayAbandon({} as never, SID);
    await flush();
    expect(sent, "the frame must actually reach the stream").toHaveLength(1);

    const frame = lastFrame(sent);
    // The exact type string is load-bearing: change it and the relay never dispatches this, so this
    // assertion must fail if the frame is renamed.
    expect(frame["type"]).toBe("session_abandon");
    expect(Buffer.from(frame["session_id"] as Uint8Array)).toEqual(Buffer.from(SID));

    client.dispatchForTest({ type: "session_abandon_ok", released: true });
    expect(await p).toEqual({ released: true });
  });

  it("★★★ released:false from the relay is carried through truthfully", async () => {
    const client = await makeClient();
    installStream(client);
    const p = client.relayAbandon({} as never, SID);
    await flush();
    client.dispatchForTest({ type: "session_abandon_ok", released: false });
    expect(await p).toEqual({ released: false });
  });

  it("★★★ a session_abandon_refused ack resolves as refused, with the reason", async () => {
    const client = await makeClient();
    installStream(client);
    const p = client.relayAbandon({} as never, SID);
    await flush();
    client.dispatchForTest({ type: "session_abandon_refused", reason: "not_a_participant" });
    expect(await p).toEqual({ refused: "not_a_participant" });
  });

  it("★★★ a silent relay times out as failed — never hangs the caller", async () => {
    vi.useFakeTimers();
    try {
      const client = await makeClient();
      installStream(client);
      const p = client.relayAbandon({} as never, SID);
      // Nothing dispatched: the relay never answers. The ack race must resolve to a failure.
      await vi.advanceTimersByTimeAsync(10_000);
      expect(await p).toEqual({ failed: "no_reply" });
    } finally {
      vi.useRealTimers();
    }
  });
});
