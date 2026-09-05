/**
 * DOD-M15-CORROBORATE-1, client leg — a relay's witness alert reaches a PERSON, and only if the
 * relay can prove it said it.
 *
 * The relay half is worth nothing on its own. A frame the daemon decodes and drops is the shape
 * this milestone keeps finding: the guard fires, correctly, and the only consumer is a file nobody
 * opens. What the operator needs is (1) that something was observed, (2) by whom, (3) whether they
 * can show it to anyone, and (4) how much one witness is actually worth.
 *
 * Four things asserted here that are easy to get backwards:
 *   - a MALFORMED alert reports NOTHING as an alert, because a relay that cannot frame this
 *     correctly must not be able to manufacture an accusation against a counterparty who did
 *     nothing — but it DOES reach the operator as "your witness layer is not working";
 *   - a relay that DECLARES an identity and does not prove it is refused. Missing, malformed and
 *     mismatched signatures take one path;
 *   - an alert naming a session this client does not hold on this relay is refused outright;
 *   - a well-formed alert does NOT freeze or end the session. This daemon freezes on its OWN check
 *     of an inbound frame; freezing on a remote party's say-so would hand every relay a kill switch.
 *
 * The TBS is rebuilt here from the wire fields rather than imported, so a drift between the relay's
 * builder and the client's is a failure rather than a shared mistake.
 */
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { generateKeypair } from "@cello-protocol/crypto";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { AgentRelayClient, type RelayWitnessAlert } from "../session-relay-client.js";
import { makeFakeRelay, tick, noopLogger } from "./relay-client-fake.js";

const SESSION_ID = new Uint8Array(16).fill(0x2f);
const SESSION_HEX = Buffer.from(SESSION_ID).toString("hex");
const REASON = "leaf_signed_by_neither_participant";
const OBSERVED_AT = 1_760_000_000_000;

interface LogLine { event: string; ctx: Record<string, unknown> }
interface Unreadable { relayPeerId: string; why: string }

function recordingLogger(errors: LogLine[]) {
  return {
    debug: () => {}, info: () => {}, warn: () => {},
    error: (event: string, ctx?: Record<string, unknown>) => { errors.push({ event, ctx: ctx ?? {} }); },
  } as unknown as typeof noopLogger;
}

/** Independently reconstructed — the relay's own builder is in the other repo. */
function witnessTbs(sessionId: Uint8Array, submitterIsCounterparty: boolean, observedAt = OBSERVED_AT): Uint8Array {
  return new Uint8Array(
    createHash("sha256")
      .update(encodeCbor(["CELLO-RELAY-WITNESS-v1", sessionId, REASON, observedAt, submitterIsCounterparty]))
      .digest(),
  );
}

async function connectedClient(opts: {
  onWitnessAlert?: (a: RelayWitnessAlert) => void;
  onWitnessUnreadable?: (relayPeerId: string, why: string) => void;
  errors?: LogLine[];
}) {
  const kp = generateKeypair();
  const relay = makeFakeRelay();
  const client = new AgentRelayClient({
    relayPeerId: "12D3KooWRelay",
    relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
    keyProvider: kp,
    senderPubkey: await kp.getPublicKey(),
    logger: opts.errors ? recordingLogger(opts.errors) : noopLogger,
    ...(opts.onWitnessAlert ? { onWitnessAlert: opts.onWitnessAlert } : {}),
    ...(opts.onWitnessUnreadable ? { onWitnessUnreadable: opts.onWitnessUnreadable } : {}),
  });
  client.registerSession(SESSION_HEX, relay.node, undefined, undefined, new Uint8Array(32).fill(0x9c));
  // Drive the handshake so the reader loop is live and dispatching inbound frames.
  const submit = client.submitMessageHash(relay.node, SESSION_ID, new Uint8Array(32).fill(3));
  await tick();
  relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
  await tick();
  relay.push({ type: "relay_auth_ok" });
  await tick();
  relay.push({ type: "hash_submit_ack", sequence_number: 1 });
  expect((await submit).ok, "precondition: the client must be authenticated and reading").toBe(true);
  return { client, relay };
}

/** A frame from a relay that names itself and proves it, the way a live relay does. */
async function signedAlert(over: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  const relayKp = generateKeypair();
  const relayId = Buffer.from(await relayKp.getPublicKey()).toString("hex");
  const submitterIsCounterparty = (over["submitter_is_counterparty"] as boolean | undefined) ?? true;
  return {
    type: "session_witness_alert",
    session_id: SESSION_ID,
    reason: REASON,
    relay_id: relayId,
    observed_at: OBSERVED_AT,
    submitter_is_counterparty: submitterIsCounterparty,
    witness_signature: await relayKp.sign(witnessTbs(SESSION_ID, submitterIsCounterparty)),
    ...over,
  };
}

describe("DOD-M15-CORROBORATE-1 (client): a relay's witness alert reaches the operator", () => {
  it("★★★ a SIGNED alert is handed on with its cause, its witness, and marked provable", async () => {
    const seen: RelayWitnessAlert[] = [];
    const errors: LogLine[] = [];
    const { client, relay } = await connectedClient({ onWitnessAlert: (a) => { seen.push(a); }, errors });

    const frame = await signedAlert();
    relay.push(frame);
    await tick();

    expect(seen.length, "the alert must reach the notice surface, not stop at the log").toBe(1);
    expect(seen[0]).toEqual({
      sessionIdHex: SESSION_HEX,
      reason: REASON,
      relayId: frame["relay_id"],
      observedAt: OBSERVED_AT,
      submitterIsCounterparty: true,
      witnessPeerId: "12D3KooWRelay",
      // The relay proved it said this, so the operator holds something showable.
      verifiable: true,
    });
    // BOTH halves — the log line is the durable forensic record and stays.
    expect(errors.map((e) => e.event)).toContain("session.relay.witness.alert");
    client.close();
  });

  it("★★ a relay that names NO identity is still reported, marked as not provable", async () => {
    const seen: RelayWitnessAlert[] = [];
    const { client, relay } = await connectedClient({ onWitnessAlert: (a) => { seen.push(a); } });
    relay.push({
      type: "session_witness_alert", session_id: SESSION_ID, reason: REASON,
      observed_at: OBSERVED_AT, submitter_is_counterparty: false,
    });
    await tick();
    expect(seen.length, "losing a genuine warning is worse than losing its transferability").toBe(1);
    expect(seen[0]!.relayId, "absent, not invented — the operator must be able to tell").toBeNull();
    expect(seen[0]!.verifiable, "and they must be told they cannot show this to anyone").toBe(false);
    expect(seen[0]!.submitterIsCounterparty).toBe(false);
    client.close();
  });

  /**
   * A DECLARED IDENTITY MUST BE PROVEN. Missing, malformed and mismatched take one path — omitting
   * the proof is the cheapest way to dodge it, so it cannot be the lenient case.
   *
   * The exemplars come from the predicate: the field simply absent; a 63-byte signature (the length
   * check); a signature over a DIFFERENT `submitter_is_counterparty` than the frame carries (the
   * verify itself — and the field an attacker would most want to flip); and a relay_id that is not
   * a pubkey at all.
   */
  it.each([
    ["no signature at all", async () => { const f = await signedAlert(); delete f["witness_signature"]; return f; }],
    ["a short signature", async () => signedAlert({ witness_signature: new Uint8Array(63).fill(9) })],
    ["a signature over a different claim", async () => {
      const relayKp = generateKeypair();
      return {
        type: "session_witness_alert", session_id: SESSION_ID, reason: REASON,
        relay_id: Buffer.from(await relayKp.getPublicKey()).toString("hex"),
        observed_at: OBSERVED_AT,
        submitter_is_counterparty: true,
        // signed as though the submitter had NOT been the counterparty
        witness_signature: await relayKp.sign(witnessTbs(SESSION_ID, false)),
      };
    }],
    ["a relay_id that is not a pubkey", async () => signedAlert({ relay_id: "relay-eu-central-1" })],
  ])("★★ a relay that declares an identity and sends %s is REFUSED", async (_label, build) => {
    const seen: RelayWitnessAlert[] = [];
    const unreadable: Unreadable[] = [];
    const errors: LogLine[] = [];
    const { client, relay } = await connectedClient({
      onWitnessAlert: (a) => { seen.push(a); },
      onWitnessUnreadable: (relayPeerId, why) => { unreadable.push({ relayPeerId, why }); },
      errors,
    });

    relay.push(await build());
    await tick();

    expect(seen, "a claimed identity that is not proven is not an observation").toEqual([]);
    expect(errors.map((e) => e.event)).toContain("session.relay.witness.malformed");
    expect(unreadable.length, "and the operator hears that their witness layer is not working").toBe(1);
    client.close();
  });

  it("★★★ an alert naming a session this client does not hold is refused as an observation — and still reaches the operator", async () => {
    /**
     * `wellFormed` checks shape only. Without this, any relay the agent is authenticated to could
     * push alerts naming arbitrary session ids — including conversations carried by a DIFFERENT
     * relay — and they would land in the inbox as statements of fact about a counterparty.
     */
    const seen: RelayWitnessAlert[] = [];
    const unreadable: Unreadable[] = [];
    const errors: LogLine[] = [];
    const { client, relay } = await connectedClient({
      onWitnessAlert: (a) => { seen.push(a); },
      onWitnessUnreadable: (relayPeerId, why) => { unreadable.push({ relayPeerId, why }); },
      errors,
    });

    const other = new Uint8Array(16).fill(0x77);
    const relayKp = generateKeypair();
    relay.push({
      type: "session_witness_alert", session_id: other, reason: REASON,
      relay_id: Buffer.from(await relayKp.getPublicKey()).toString("hex"),
      observed_at: OBSERVED_AT, submitter_is_counterparty: true,
      witness_signature: await relayKp.sign(witnessTbs(other, true)),
    });
    await tick();

    expect(seen, "a relay may not speak about a conversation it does not carry for us").toEqual([]);
    expect(errors.map((e) => e.event)).toContain("session.relay.witness.unknown_session");
    /**
     * ⚠️ REFUSED AS AN OBSERVATION, BUT NOT BINNED IN SILENCE. The relay's queue is keyed by pubkey
     * and drains destructively, so by this point its copy is already gone — a client that quietly
     * discarded this would leave the operator a clean inbox and no way to know anything arrived.
     * It reaches the neutral surface, naming no session and no party.
     */
    expect(unreadable).toEqual([{ relayPeerId: "12D3KooWRelay", why: "session_not_held_here" }]);
    client.close();
  });

  /**
   * Field-shape cases, exemplars taken from the predicate rather than from intent: a 15-byte session
   * id (the length check), the literal `undefined` for an omitted boolean, a string where a number
   * belongs, and a reason a future version might send that this build does not understand.
   */
  it.each([
    ["a short session_id", { session_id: new Uint8Array(15).fill(0x2f) }],
    ["a missing submitter flag", { submitter_is_counterparty: undefined }],
    ["a non-numeric observed_at", { observed_at: "recently" }],
    ["a reason this build does not know", { reason: "something_else_entirely" }],
  ])("★★ %s reports NOTHING as an alert — a relay must not be able to manufacture an accusation", async (_label, override) => {
    const seen: RelayWitnessAlert[] = [];
    const unreadable: Unreadable[] = [];
    const errors: LogLine[] = [];
    const { client, relay } = await connectedClient({
      onWitnessAlert: (a) => { seen.push(a); },
      onWitnessUnreadable: (relayPeerId, why) => { unreadable.push({ relayPeerId, why }); },
      errors,
    });

    relay.push({ ...(await signedAlert()), ...override });
    await tick();

    expect(seen, "a frame this build cannot read is a relay fault, not evidence about anyone").toEqual([]);
    // And it is NOT silent: the relay operator's build is wrong or skewed and someone must be able
    // to find that out — from the inbox, not only from a log file.
    expect(errors.map((e) => e.event)).toContain("session.relay.witness.malformed");
    expect(errors.map((e) => e.event)).not.toContain("session.relay.witness.alert");
    expect(unreadable.length).toBe(1);
    client.close();
  });

  it("★★ the alert reaches the surface AND leaves the session alive — one witness reports, it does not rule", async () => {
    /**
     * ⚠️ ASSERTS BOTH HALVES IN ONE TEST, and the earlier version did not — which made it hollow.
     * Deleting the whole `session_witness_alert` branch left the frame falling off the end of the
     * dispatch chain, the session untouched, and this test green: it asserted the ABSENCE of code
     * that was never written. The callback assertion is what ties it to the branch existing.
     */
    const seen: RelayWitnessAlert[] = [];
    const { client, relay } = await connectedClient({ onWitnessAlert: (a) => { seen.push(a); } });
    relay.push(await signedAlert());
    await tick();
    expect(seen.length, "the branch must exist and fire, or the rest of this proves nothing").toBe(1);
    expect(client.hasSessions(), "a relay's observation must not tear down the conversation").toBe(true);

    // And the session still works: the next send is submitted and acked as normal.
    const next = client.submitMessageHash(relay.node, SESSION_ID, new Uint8Array(32).fill(4));
    await tick();
    relay.push({ type: "hash_submit_ack", sequence_number: 2 });
    const res = await next;
    expect(res.ok, "the session must still carry traffic after an alert").toBe(true);
    client.close();
  });
});
