/**
 * 017-SEAL — a busy provider still seals every session (Part 1: the rate-limited sign-in retries).
 *
 * Step 0 (live, m10e) proved the stall: a provider that signs in to the relay more than 20 times a
 * minute has its 21st sign-in refused `relay.auth.rate_limited` (with a `retry_after_ms`); the
 * daemon mislabelled that as `relay_unavailable`, fell back to a directory-only seal on BOTH sides
 * at once, and each side then refused the other's co-sign (`seal_rejected_by_counterparty`). The
 * SEAL never completed.
 *
 * S2 pins Part 1 at the exact boundary the stall passed through — `AgentRelayClient.submitLeaf`.
 * A fake relay refuses the FIRST auth `rate_limited` and admits every later one, exactly as the real
 * relay's window does once it resets. The submit must WAIT the relay's stated window and resubmit,
 * succeeding on the retry — and it must never report the fallback-triggering `relay_unavailable`.
 *
 * Real Ed25519 (the auth signature and the SEAL leaf are really signed); the relay is the shared
 * `makeFakeRelayServer` rig, extended only with a defaulted `onAuth` hook. No daemon, no SQLCipher:
 * this is the client's submit/retry logic, and S1 (the live j-live-inquiry journey) is the
 * end-to-end proof over real keys, real SQLCipher and the real relay binary.
 *
 * Revert check (017-SEAL): remove the `rate_limited` promotion in `#doSubmitOnce` and this fails —
 * `submitLeaf` returns `relay_unavailable`, the throttle loop never fires, and `.ok` is false.
 */
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { generateKeypair } from "@cello-protocol/crypto";
import { encodeSealPayload } from "@cello-protocol/protocol-types";
import { AgentRelayClient, LEAF_KIND_CTRL } from "../session-relay-client.js";
import { fakeRelayAnchor } from "./relay-client-fake.js";
import {
  makeFakeRelayServer, FakeRelayAwareNode, FAKE_RELAY_PEER_ID, FAKE_RELAY_ADDR,
} from "./helpers/fake-relay-server.js";
import type { Logger } from "../types.js";

interface LogEvent { event: string; ctx: Record<string, unknown> }
function recordingLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const rec = (event: string, ctx?: Record<string, unknown>) => { events.push({ event, ctx: ctx ?? {} }); };
  return { logger: { debug: rec, info: rec, warn: rec, error: rec }, events };
}

/** A real SEAL ctrl payload and the content hash the client binds it to. */
function sealFor(sid: Uint8Array): { payload: Uint8Array; contentHash: Uint8Array } {
  const payload = encodeSealPayload({
    session_id: sid,
    final_root: new Uint8Array(32).fill(0x33),
    close_timestamp: 1_700_000_000_000,
    attestation: "PENDING",
  });
  const contentHash = new Uint8Array(
    createHash("sha256").update(new Uint8Array([LEAF_KIND_CTRL])).update(payload).digest(),
  );
  return { payload, contentHash };
}

describe("017-SEAL S2 — a rate-limited relay sign-in retries after retry_after_ms, never falls back", () => {
  it("the first sign-in is throttled; the SEAL submit waits the window out and succeeds on the retry", async () => {
    const { logger, events } = recordingLogger();
    const kp = generateKeypair();

    // The relay rejects the FIRST auth handshake `rate_limited`, naming a SHORT window so the test
    // does not actually wait a minute. Every later sign-in (a fresh window) is admitted — the
    // self-clearing shape of the real limiter.
    const RETRY_AFTER_MS = 40;
    let refusedOnce = false;
    const relay = makeFakeRelayServer({
      onAuth: (attempt) => {
        if (attempt === 1) { refusedOnce = true; return { reason: "rate_limited", retry_after_ms: RETRY_AFTER_MS }; }
        return undefined;
      },
    });
    const node = new FakeRelayAwareNode(relay);

    const client = new AgentRelayClient({
      relayPeerId: FAKE_RELAY_PEER_ID,
      relayAddrs: [FAKE_RELAY_ADDR],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger,
    });

    const sid = new Uint8Array(16).fill(0x11);
    client.registerSession(
      Buffer.from(sid).toString("hex"), node as never, undefined, await fakeRelayAnchor(), new Uint8Array(32).fill(0x9c),
    );

    const { payload, contentHash } = sealFor(sid);
    const result = await client.submitLeaf(node as never, sid, contentHash, LEAF_KIND_CTRL, payload);

    // The first auth really was throttled (otherwise this proves nothing about the retry).
    expect(refusedOnce, "the fake relay must have refused the first sign-in").toBe(true);
    // The submit retried and SUCCEEDED — the seal took the relay-witnessed path.
    expect(result.ok, `submit should succeed after the throttle clears: ${JSON.stringify(result)}`).toBe(true);
    // The throttle was waited out here, not surfaced to the caller as a fallback-triggering outage.
    expect(events.some((e) => e.event === "session.relay.submit.throttled"), "the throttle-and-retry path must have fired").toBe(true);

    client.close();
  });
});
