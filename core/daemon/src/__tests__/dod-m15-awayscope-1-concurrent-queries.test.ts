/**
 * DOD-M15-AWAYSCOPE-1 — two sessions on ONE relay client, asked at the same time.
 *
 * ── WHY THIS FILE EXISTS SEPARATELY ──────────────────────────────────────────────────────────────
 *
 * Every other test of this feature uses a fake relay client that REPLACES `queryLiveness` outright,
 * so the code that matches an answer to its question never runs. The unit review found the defect
 * that hides behind exactly that: `#pendingLiveness` was a single resolver slot, one
 * `AgentRelayClient` serves every session an agent holds on a relay, and both consumers fan out
 * with `Promise.all`.
 *
 * The consequence was not subtle and was invisible to a one-session test. `cello status` with two
 * open conversations fired two queries down one stream; the second overwrote the first's resolver;
 * the first answer to arrive resolved the WRONG session's promise, so one counterparty's attendance
 * appeared on the other's row — and the orphaned promise waited the full submit timeout, blew the
 * caller's budget, and made every row come back unenriched.
 *
 * So this drives the REAL client against a stub stream, which is the only way the matching code is
 * exercised at all.
 */

import { describe, it, expect } from "vitest";
import { AgentRelayClient } from "../session-relay-client.js";
import { generateKeypair } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";
import type { Stream } from "@libp2p/interface";

const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

const SID_A = new Uint8Array(16).fill(0xa1);
const SID_B = new Uint8Array(16).fill(0xb2);
const PUB_A = new Uint8Array(32).fill(0x11);
const PUB_B = new Uint8Array(32).fill(0x22);

/** A live stream, recording what was sent. `queryLiveness` never dials, so this is what it expects. */
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

async function makeClient(): Promise<AgentRelayClient> {
  const kp = await generateKeypair();
  return new AgentRelayClient({
    relayPeerId: "12D3KooWFakeRelayForConcurrency",
    relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/fake"],
    keyProvider: {
      getPublicKey: async () => kp.publicKey,
      sign: async (m: Uint8Array) => kp.sign(m),
    } as never,
    senderPubkey: kp.publicKey,
    logger: noopLogger,
  });
}

describe("DOD-M15-AWAYSCOPE-1: two concurrent liveness queries on one relay client", () => {
  it("★★ each answer goes to the session that ASKED for it, even when they come back reversed", async () => {
    const client = await makeClient();
    const captured = installStream(client);

    const a = client.queryLiveness(SID_A, PUB_A);
    const b = client.queryLiveness(SID_B, PUB_B);
    expect(captured, "both queries must actually reach the stream").toHaveLength(2);

    // REVERSED on purpose: B answers first. A single-slot implementation hands B's answer to A's
    // promise — A then reports B's attendance, and B waits out the full timeout.
    client.dispatchForTest({
      type: "session_liveness_response",
      session_id: SID_B, counterparty_pubkey: PUB_B,
      liveness: "alive", observed_at: 2_000, attendance: "offline", attendance_observed_at: 2_001,
    });
    client.dispatchForTest({
      type: "session_liveness_response",
      session_id: SID_A, counterparty_pubkey: PUB_A,
      liveness: "alive", observed_at: 1_000, attendance: "unattended", attendance_observed_at: 1_001,
    });

    const [ra, rb] = await Promise.all([a, b]);
    expect(ra.attendance, "session A must get A's answer").toBe("unattended");
    expect(ra.attendanceObservedAt).toBe(1_001);
    expect(rb.attendance, "session B must get B's answer").toBe("offline");
    expect(rb.attendanceObservedAt).toBe(2_001);
  });

  it("★★ an answer nobody asked for is DROPPED, not given to whoever is waiting", async () => {
    /**
     * A late answer to a query that already timed out arrives on a stream where another query is
     * outstanding. Handing it over is the same defect from the other direction — the operator reads
     * a third party's attendance on this session's row, sourced from a question this session never
     * asked.
     */
    const client = await makeClient();
    installStream(client);

    const a = client.queryLiveness(SID_A, PUB_A);
    // An answer for a session that is NOT the one outstanding.
    client.dispatchForTest({
      type: "session_liveness_response",
      session_id: SID_B, counterparty_pubkey: PUB_B,
      liveness: "alive", observed_at: 9, attendance: "attended", attendance_observed_at: 9,
    });
    // A's own answer, after it.
    client.dispatchForTest({
      type: "session_liveness_response",
      session_id: SID_A, counterparty_pubkey: PUB_A,
      liveness: "gone", observed_at: 5,
    });
    const ra = await a;
    expect(ra.liveness, "A must get A's answer, not the stray one that arrived first").toBe("gone");
    expect(ra.attendance, "and 'gone' carries no attendance at all").toBeUndefined();
  });

  it("★★ a REFUSAL settles every outstanding query, because it names none of them", async () => {
    /**
     * The relay refuses without echoing the session or the subject — deliberately, because telling
     * "no such session" from "not your session" is the enumeration signal. So there is nothing to
     * key a refusal on, and the only sound reading is that it applies to all of them: the refusal is
     * a property of the CALLER, and the caller is the same for every query on this stream.
     *
     * The alternative — dropping it — leaves every query to time out, which turns a fast, definite
     * "I won't tell you" into a slow "I don't know" and blows the caller's budget for the whole read.
     */
    const client = await makeClient();
    installStream(client);

    const a = client.queryLiveness(SID_A, PUB_A);
    const b = client.queryLiveness(SID_B, PUB_B);
    client.dispatchForTest({ type: "session_liveness_refused", reason: "not_a_participant" });

    const [ra, rb] = await Promise.all([a, b]);
    for (const [name, r] of [["A", ra], ["B", rb]] as const) {
      expect(r.refused, `${name} must learn it was refused`).toBe(true);
      expect(r.liveness, `${name} must read 'unknown' — a refusal is not an observation`).toBe("unknown");
      expect(r.attendance, `${name} must carry no attendance`).toBeUndefined();
    }
  });
});
