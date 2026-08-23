/**
 * The controllable fake relay stream + node, shared by every `AgentRelayClient` test.
 *
 * Extracted from `session-relay-client.test.ts` when `dod-m15-sealwire-1-sender-leg.test.ts` needed
 * the same rig. Moved rather than copied: a second hand-written relay stub would drift from this one
 * exactly as the trust-signal envelope fixture drifted from the real wire format — silently, until a
 * field was appended and only one of the two knew about it.
 *
 * It captures outbound frames decoded from the length-prefixed wire, and lets a test push inbound
 * frames the client's reader consumes.
 */

import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import type { Logger } from "../types.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

export const noopLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
} as unknown as Logger;

/** A node that cannot open a stream — for asserting failures that must never reach the wire. */
export const fakeNode = {
  dial: async () => {},
  newStream: async () => { throw new Error("no-stream"); },
} as never;

export interface FakeRelay {
  node: never;
  push: (frame: Record<string, unknown>) => void;
  sentFrames: Record<string, unknown>[];
}

export function makeFakeRelay(): FakeRelay {
  const inbound: Uint8Array[] = [];
  let notify: (() => void) | null = null;
  let ended = false;
  const sentFrames: Record<string, unknown>[] = [];

  const stream = {
    send: (b: { subarray?: () => Uint8Array } | Uint8Array) => {
      // b is lp.encode.single(cbor) — un-frame it via lp.decode to read the CBOR back.
      const bytes = b instanceof Uint8Array ? b : (b.subarray ? b.subarray() : (b as unknown as Uint8Array));
      void (async () => {
        for await (const chunk of lp.decode([bytes] as unknown as AsyncIterable<Uint8Array>)) {
          const u8 = chunk instanceof Uint8Array ? chunk : (chunk as { subarray(): Uint8Array }).subarray();
          sentFrames.push(decode(u8) as Record<string, unknown>);
        }
      })();
    },
    close: async () => { ended = true; notify?.(); },
    async *[Symbol.asyncIterator]() {
      while (!ended) {
        while (inbound.length) yield inbound.shift()!;
        if (ended) return;
        await new Promise<void>((r) => { notify = r; });
        notify = null;
      }
    },
  };

  const push = (frame: Record<string, unknown>): void => {
    const encoded = lp.encode.single(CBOR_ENC.encode(frame) as Uint8Array);
    inbound.push(encoded instanceof Uint8Array ? encoded : (encoded as { subarray(): Uint8Array }).subarray());
    notify?.();
  };

  const node = { dial: async () => {}, newStream: async () => stream } as never;
  return { node, push, sentFrames };
}

export const tick = (): Promise<unknown> => new Promise((r) => setTimeout(r, 5));
