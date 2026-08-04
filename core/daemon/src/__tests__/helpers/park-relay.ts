/**
 * DOD-PARK-DRAIN-1 test helper — an in-process relay that actually speaks
 * `/cello/content-park/1.0.0`, so a test can park a real message and watch a RUNNING daemon
 * recover it.
 *
 * The bare HOP relay the reservation tests use is enough to prove a trigger FIRED. It is not
 * enough to prove the DoD's headline claim — that parked content is DELIVERED without a restart —
 * because its pull fails and no content ever moves. This one holds a mailbox.
 *
 * The wire contract is `packages/relay/src/content-park.ts` (authoritative), mirrored in
 * `content-park-client.ts`:
 *   deposit:  → content_park_deposit           ← content_park_deposit_ack
 *   pull:     → content_park_pull_request      ← content_park_auth_challenge
 *             → content_park_auth_response     ← content_park_pull_count, N × pull_response
 *   confirm:  → content_park_confirm           ← content_park_auth_challenge
 *             → content_park_auth_response     ← content_park_confirm_ack
 *
 * The auth challenge is issued and its response is REQUIRED, but the signature is not verified:
 * this fixture exists to exercise the CLIENT's drain, and the relay-side verification is the
 * relay repo's own test. Deposit is open by design (the blob is sealed to the recipient).
 */
import * as lp from "it-length-prefixed";
import { decode } from "cbor-x";
import { randomBytes } from "node:crypto";
import { encodeCbor, CONTENT_PARK_PROTOCOL_ID } from "@cello-protocol/protocol-types";
import { createNode } from "@cello-protocol/transport";
import type { CelloNode } from "@cello-protocol/transport";
import { generateKeypair } from "@cello-protocol/crypto";
import type { Stream } from "@libp2p/interface";

export interface ParkedRecord {
  recipientPubkeyHex: string;
  contentHashHex: string;
  sessionIdHex: string;
  ciphertext: Uint8Array;
}

export interface ParkRelay {
  node: CelloNode;
  peerId: string;
  addr: string;
  /** The mailbox, keyed `${recipientPubkeyHex}:${contentHashHex}`. Confirm-delete removes entries. */
  mailbox: Map<string, ParkedRecord>;
  /** How many pulls this relay has served — proof a drain reached the wire, not just the hook. */
  pullCount: () => number;
  stop: () => Promise<void>;
}

function toU8(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) return chunk;
  const c = chunk as { subarray?: () => Uint8Array };
  if (typeof c?.subarray === "function") return c.subarray();
  return new Uint8Array(chunk as ArrayBufferLike);
}

function bytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

const hex = (v: Uint8Array): string => Buffer.from(v).toString("hex");

/** Start a HOP relay that also serves the content park. */
export async function startParkRelay(): Promise<ParkRelay> {
  const node = await createNode({
    keyProvider: generateKeypair(),
    listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
  });
  await node.start();
  const addr = node.listenAddresses().find((a) => a.includes("/p2p/"));
  if (!addr) throw new Error("park relay has no addressed multiaddr");

  const mailbox = new Map<string, ParkedRecord>();
  let pulls = 0;

  await node.handle(CONTENT_PARK_PROTOCOL_ID, (stream: Stream) => {
    void (async () => {
      const iter = (lp.decode(stream as unknown as AsyncIterable<Uint8Array>) as AsyncIterable<unknown>)[
        Symbol.asyncIterator
      ]();
      const read = async (): Promise<Record<string, unknown> | null> => {
        const r = await iter.next();
        if (r.done) return null;
        return decode(toU8(r.value)) as Record<string, unknown>;
      };
      const send = (frame: unknown): void => {
        stream.send(lp.encode.single(encodeCbor(frame) as Uint8Array));
      };

      try {
        const first = await read();
        if (!first) return;

        if (first["type"] === "content_park_deposit") {
          const recipient = bytes(first["recipient_pubkey"]);
          const contentHash = bytes(first["content_hash"]);
          const sessionId = bytes(first["session_id"]);
          const ciphertext = bytes(first["ciphertext"]);
          if (!recipient || !contentHash || !ciphertext) {
            send({ type: "content_park_deposit_ack", ok: false, reason: "missing_fields" });
            return;
          }
          mailbox.set(`${hex(recipient)}:${hex(contentHash)}`, {
            recipientPubkeyHex: hex(recipient),
            contentHashHex: hex(contentHash),
            sessionIdHex: sessionId ? hex(sessionId) : "",
            ciphertext,
          });
          send({ type: "content_park_deposit_ack", content_hash: contentHash, ok: true });
          return;
        }

        if (first["type"] === "content_park_pull_request") {
          const recipient = bytes(first["recipient_pubkey"]);
          if (!recipient) return;
          send({ type: "content_park_auth_challenge", nonce: randomBytes(32) });
          const auth = await read();
          if (!auth || auth["type"] !== "content_park_auth_response") return;
          pulls++;
          const owned = [...mailbox.values()].filter((e) => e.recipientPubkeyHex === hex(recipient));
          send({ type: "content_park_pull_count", count: owned.length });
          for (const e of owned) {
            send({
              type: "content_park_pull_response",
              found: true,
              content_hash: Buffer.from(e.contentHashHex, "hex"),
              session_id: Buffer.from(e.sessionIdHex, "hex"),
              ciphertext: e.ciphertext,
            });
          }
          return;
        }

        if (first["type"] === "content_park_confirm") {
          const recipient = bytes(first["recipient_pubkey"]);
          const contentHash = bytes(first["content_hash"]);
          if (!recipient || !contentHash) return;
          send({ type: "content_park_auth_challenge", nonce: randomBytes(32) });
          const auth = await read();
          if (!auth || auth["type"] !== "content_park_auth_response") return;
          // Delete-on-CONFIRM: the client only confirms what it has durably ingested.
          mailbox.delete(`${hex(recipient)}:${hex(contentHash)}`);
          send({ type: "content_park_confirm_ack", content_hash: contentHash, ok: true });
          return;
        }
      } catch {
        /* the client closed mid-exchange — nothing to salvage on a fixture */
      } finally {
        await stream.close().catch(() => {});
      }
    })();
  });

  return {
    node,
    peerId: node.getPeerId(),
    addr,
    mailbox,
    pullCount: () => pulls,
    stop: async () => { await node.stop(); },
  };
}
