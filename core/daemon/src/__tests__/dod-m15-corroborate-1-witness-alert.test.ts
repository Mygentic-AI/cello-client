/**
 * DOD-M15-CORROBORATE-1, client leg — a relay's witness alert reaches a PERSON.
 *
 * The relay half is worth nothing on its own. A frame the daemon decodes and drops is the shape
 * this milestone keeps finding: the guard fires, correctly, and the only consumer is a file nobody
 * opens. What the operator needs is (1) that something was observed, (2) by whom, and (3) how much
 * one witness is actually worth — the third being the one it is easiest to overclaim.
 *
 * Two things are asserted here that are easy to get backwards:
 *   - a MALFORMED alert reports NOTHING, because a relay that cannot frame this correctly must not
 *     be able to manufacture an accusation against a counterparty who did nothing;
 *   - a well-formed alert does NOT freeze or end the session. This daemon freezes on its OWN check
 *     of an inbound frame; freezing on a remote party's say-so would hand every relay a kill switch.
 */
import { describe, it, expect } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import { AgentRelayClient, type RelayWitnessAlert } from "../session-relay-client.js";
import { makeFakeRelay, tick, noopLogger } from "./relay-client-fake.js";

const SESSION_ID = new Uint8Array(16).fill(0x2f);
const SESSION_HEX = Buffer.from(SESSION_ID).toString("hex");

interface LogLine { event: string; ctx: Record<string, unknown> }

function recordingLogger(errors: LogLine[]) {
  return {
    debug: () => {}, info: () => {}, warn: () => {},
    error: (event: string, ctx?: Record<string, unknown>) => { errors.push({ event, ctx: ctx ?? {} }); },
  } as unknown as typeof noopLogger;
}

async function connectedClient(opts: {
  onWitnessAlert?: (a: RelayWitnessAlert) => void;
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
  });
  client.registerSession(SESSION_HEX, relay.node);
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

const WELL_FORMED = {
  type: "session_witness_alert",
  session_id: SESSION_ID,
  reason: "leaf_signed_by_neither_participant",
  relay_id: "relay-eu-central-1",
  observed_at: 1_760_000_000_000,
  submitter_is_counterparty: true,
};

describe("DOD-M15-CORROBORATE-1 (client): a relay's witness alert reaches the operator", () => {
  it("★★★ a well-formed alert is handed on with its cause, its witness, and who the relay says submitted it", async () => {
    const seen: RelayWitnessAlert[] = [];
    const errors: LogLine[] = [];
    const { client, relay } = await connectedClient({ onWitnessAlert: (a) => { seen.push(a); }, errors });

    relay.push(WELL_FORMED);
    await tick();

    expect(seen.length, "the alert must reach the notice surface, not stop at the log").toBe(1);
    expect(seen[0]).toEqual({
      sessionIdHex: SESSION_HEX,
      reason: "leaf_signed_by_neither_participant",
      relayId: "relay-eu-central-1",
      observedAt: 1_760_000_000_000,
      submitterIsCounterparty: true,
    });
    // BOTH halves — the log line is the durable forensic record and stays.
    expect(errors.map((e) => e.event)).toContain("session.relay.witness.alert");
    client.close();
  });

  it("★★ an alert from a relay that could not name itself still lands, with the witness marked unnamed", async () => {
    const seen: RelayWitnessAlert[] = [];
    const { client, relay } = await connectedClient({ onWitnessAlert: (a) => { seen.push(a); } });
    const noRelayId: Record<string, unknown> = { ...WELL_FORMED, submitter_is_counterparty: false };
    delete noRelayId["relay_id"];
    relay.push(noRelayId);
    await tick();
    expect(seen.length).toBe(1);
    expect(seen[0]!.relayId, "absent, not invented — the operator must be able to tell").toBeNull();
    expect(seen[0]!.submitterIsCounterparty).toBe(false);
    client.close();
  });

  /**
   * Each case is a field a relay could get wrong or omit. The exemplars are taken from the
   * predicate, not from intent: a 15-byte session id (the length check), the literal `undefined`
   * for an omitted boolean, a string where a number belongs, and the reason string a future
   * version might send that this build does not understand.
   */
  it.each([
    ["a short session_id", { session_id: new Uint8Array(15).fill(0x2f) }],
    ["a missing submitter flag", { submitter_is_counterparty: undefined }],
    ["a non-numeric observed_at", { observed_at: "recently" }],
    ["a reason this build does not know", { reason: "something_else_entirely" }],
  ])("★★ %s reports NOTHING to the operator — a relay must not be able to manufacture an accusation", async (_label, override) => {
    const seen: RelayWitnessAlert[] = [];
    const errors: LogLine[] = [];
    const { client, relay } = await connectedClient({ onWitnessAlert: (a) => { seen.push(a); }, errors });

    relay.push({ ...WELL_FORMED, ...override });
    await tick();

    expect(seen, "a frame this build cannot read is a relay fault, not evidence about anyone").toEqual([]);
    // And it is NOT silent: the relay operator's build is wrong or skewed and someone must be able
    // to find that out.
    expect(errors.map((e) => e.event)).toContain("session.relay.witness.malformed");
    expect(errors.map((e) => e.event)).not.toContain("session.relay.witness.alert");
    client.close();
  });

  it("★★ the alert does not close the session or the relay client — one witness reports, it does not rule", async () => {
    const { client, relay } = await connectedClient({ onWitnessAlert: () => {} });
    relay.push(WELL_FORMED);
    await tick();
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
