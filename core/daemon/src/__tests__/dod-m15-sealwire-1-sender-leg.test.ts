/**
 * THE CLIENT ACTUALLY SENDS THE SEAL PAYLOAD — `DOD-M15-SEALWIRE-1` bullets 3+4, THE SENDER LEG.
 *
 * ─── The finding this exists for ───────────────────────────────────────────────────────────────
 *
 * Review pass 1 on the directory wiring found that **the whole chain was built except its head.**
 * Four legs shipped — the verifier, the relay's wire acceptance, the relay's store-and-forward, and
 * the directory wiring — and every one of them was reviewed and green. Nobody produced the bytes.
 *
 * `submitSealLeaf` computed the payload, hashed it, and dropped it on the floor:
 *
 *     const sealPayload = encodeSealPayload({ session_id, final_root, close_timestamp, "PENDING" });
 *     const contentHash = sha256(0x02 ‖ sealPayload);
 *     await relayClient.submitLeaf(node, sessionId, contentHash, LEAF_KIND_CTRL);   // ← payload lost
 *
 * `submitLeaf` had no parameter for it, so the `hash_submit` frame carried none. In production the
 * directory's new check would have returned `not_carried` on **every seal, forever**, while logging
 * that the relay was on an old build — sending an operator to compare versions on the wrong machine
 * for a value the client never sent.
 *
 * It is also exactly why my revert test on the wiring was so quiet: with no producer, the mutation
 * changed nothing for 1154 of 1157 tests.
 *
 * ─── ⚠️ THE COUNTERBALANCE, NAMED BEFORE THE CODE ──────────────────────────────────────────────
 *
 * **This teaches the client to put leaf CONTENT on the relay, and the relay is the party this
 * protocol exists to keep content away from.** INV-3 is that a forwarding relay sees ciphertext.
 * A parameter that accepts content is a parameter a future caller can hand a message to.
 *
 * It is safe for a SEAL ctrl leaf and for nothing else: the payload is `[session_id, final_root,
 * close_timestamp, "PENDING"]`, and the relay already knows all four — it assigned the session, it
 * built the tree the root comes from, and it stamped the leaf. Nothing is disclosed. That reasoning
 * does not survive one leaf kind further: a `msg` leaf's content is the operator's plaintext.
 *
 * So the guard is refusal, not filtering, and it is enforced on BOTH ends independently. The relay
 * already refuses the whole frame for content on a non-ctrl leaf. The client refuses to send it —
 * because by the time the relay refuses, the operator's message has already crossed the wire, and
 * the refusal destroys their send rather than protecting it.
 *
 * ─── And the ctrl direction is refused too, which is the part that stops this recurring ────────
 *
 * A ctrl submit with NO payload is now a named local failure rather than a silent downgrade. That is
 * deliberate: silent-downgrade is the precise shape of the defect above, and it survived four
 * reviewed legs. A dropped argument now breaks the seal loudly on the machine that dropped it,
 * instead of surfacing three hops away as a false claim about someone else's build version.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { decode } from "cbor-x";
import { generateKeypair, verify } from "@cello-protocol/crypto";
import { encodeSealPayload, decodeSealPayload } from "@cello-protocol/protocol-types";
import { AgentRelayClient, LEAF_KIND_MSG, LEAF_KIND_CTRL, LEAF_KIND_DOC } from "../session-relay-client.js";
import { makeFakeRelay, tick, noopLogger } from "./relay-client-fake.js";

async function connectedClient(): Promise<{
  client: AgentRelayClient;
  relay: ReturnType<typeof makeFakeRelay>;
  sid: Uint8Array;
}> {
  const kp = generateKeypair();
  const client = new AgentRelayClient({
    relayPeerId: "12D3KooWRelay",
    relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
    keyProvider: kp,
    senderPubkey: await kp.getPublicKey(),
    logger: noopLogger,
  });
  const relay = makeFakeRelay();
  const sid = new Uint8Array(16).fill(0x11);
  client.registerSession(Buffer.from(sid).toString("hex"), relay.node);
  return { client, relay, sid };
}

/** Drive the challenge → auth_ok handshake the client performs on its first submit. */
async function authenticate(relay: ReturnType<typeof makeFakeRelay>): Promise<void> {
  await tick();
  relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
  await tick();
  relay.push({ type: "relay_auth_ok" });
  await tick();
}

/** A real SEAL payload for a session, and the content hash the client derives from it. */
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

describe("DOD-M15-SEALWIRE-1 sender leg: the SEAL payload reaches the wire, and only it", () => {
  it("★ the ANCHOR — an ordinary MESSAGE submit carries NO content, and that must never change", async () => {
    /**
     * ⚠️ PINNED FIRST, AND IT IS THE INVARIANT, NOT A FORMALITY.
     *
     * Every other assertion here is about getting content ONTO the relay. This one is the reason
     * that is dangerous. A regression that widened the carry to messages would satisfy the seal
     * tests below perfectly while handing the forwarding relay every word of every conversation.
     */
    const { client, relay, sid } = await connectedClient();
    const submit = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(1), LEAF_KIND_MSG);
    await authenticate(relay);
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    expect((await submit).ok).toBe(true);

    const frames = relay.sentFrames.filter((f) => f["type"] === "hash_submit");
    expect(frames.length, "no submit went out, so this proves nothing").toBe(1);
    expect(
      "content_bytes" in frames[0]!,
      "a forwarding relay must see ciphertext — a message leaf must never carry its content",
    ).toBe(false);
    client.close();
  });

  it("★★ A SEAL CTRL SUBMIT CARRIES ITS PAYLOAD — the leg that was missing entirely", async () => {
    /**
     * ⚠️ THE ASSERTION THIS FILE EXISTS FOR.
     *
     * Asserted on the DECODED FRAME rather than on the argument, because the defect was not a wrong
     * argument — it was a correct value with nowhere to go. Only the wire can tell those apart.
     */
    const { client, relay, sid } = await connectedClient();
    const { payload, contentHash } = sealFor(sid);

    const submit = client.submitLeaf(relay.node, sid, contentHash, LEAF_KIND_CTRL, payload);
    await authenticate(relay);
    relay.push({ type: "hash_submit_ack", sequence_number: 4 });
    expect((await submit).ok, "the seal submit must succeed").toBe(true);

    const frame = relay.sentFrames.filter((f) => f["type"] === "hash_submit")[0]!;
    const carried = frame["content_bytes"];
    expect(carried, "without these bytes the directory cannot check the relay against a client signature").toBeTruthy();

    // Compared as bytes: CBOR round-trips a Uint8Array to a Buffer, and toEqual treats those as
    // different types while the bytes are identical.
    const carriedU8 = carried instanceof Uint8Array ? carried : new Uint8Array(carried as ArrayBuffer);
    expect(Buffer.from(carriedU8).equals(Buffer.from(payload)), "the payload must arrive unaltered").toBe(true);
  });

  it("★★ THE CARRIED BYTES HASH TO THE SUBMITTED content_hash — otherwise the directory refuses", async () => {
    /**
     * The binding, checked from the wire rather than assumed from the call.
     *
     * If the payload and the hash ever came from different derivations, the directory's
     * `PAYLOAD_UNBOUND` fires and it accuses **the relay of tampering** — for a mismatch the client
     * created. That is the worst possible failure of this leg: a correct relay blamed by name, in an
     * error log written to sound like an attack.
     *
     * So this recomputes `SHA-256(0x02 ‖ payload)` from the bytes that actually went out and compares
     * it to the `content_hash` inside the signed Structure 1 of the same frame.
     *
     * ⚠️ THIS ALONE WAS HOLLOW, AND REVIEW PASS 2 SAID SO. It binds bytes the TEST supplied to a
     * hash the TEST supplied, so it proves the frame carries what it was given — not that the
     * production derivation gives the right thing. Making the parameter required catches an OMITTED
     * argument; nothing caught a SUBSTITUTED one. A manager that re-derives the payload rather than
     * passing the one it hashed compiles cleanly and was green here.
     *
     * Closed in TWO places rather than by widening this test:
     *   - `submitLeaf` now re-derives and compares before sending, so the mismatch is a LOCAL
     *     refusal (`seal_payload_unbound`) on the machine that caused it — asserted in the next
     *     test — instead of an accusation published against a relay three hops away.
     *   - and the manager's own derivation is covered end to end by `m8c-away-1.test.ts`, which
     *     drives `submitSealLeaf` through a real `AgentRelayClient`. MEASURED: substituting a
     *     re-derived payload at `session-node-manager.ts` turns that test red. Named here so the
     *     coverage is findable, because it lives in a file about something else entirely.
     */
    const { client, relay, sid } = await connectedClient();
    const { payload, contentHash } = sealFor(sid);

    const submit = client.submitLeaf(relay.node, sid, contentHash, LEAF_KIND_CTRL, payload);
    await authenticate(relay);
    relay.push({ type: "hash_submit_ack", sequence_number: 4 });
    await submit;

    const frame = relay.sentFrames.filter((f) => f["type"] === "hash_submit")[0]!;
    const carried = frame["content_bytes"] as Uint8Array;
    const rederived = createHash("sha256")
      .update(new Uint8Array([LEAF_KIND_CTRL]))
      .update(new Uint8Array(carried))
      .digest();

    // Structure 1 = [1, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp] — the
    // SIGNED bytes, which is the value the directory binds against.
    const s1 = decode(frame["structure1_cbor"] as Uint8Array) as unknown[];
    const signedHash = s1[1] as Uint8Array;
    expect(
      Buffer.from(rederived).equals(Buffer.from(new Uint8Array(signedHash))),
      "a payload that does not hash to the SIGNED content_hash makes the directory accuse the relay of tampering",
    ).toBe(true);

    // And the payload must name THIS session — the relay binds it at the wire and refuses a replay.
    const decoded = decodeSealPayload(new Uint8Array(carried));
    expect(decoded, "the bytes must decode as a SEAL payload").toBeTruthy();
    expect(
      Buffer.from(decoded!.session_id).equals(Buffer.from(sid)),
      "a payload naming another session is refused by the relay before it ever reaches the directory",
    ).toBe(true);
  });

  it("★★ THE SENT ROW'S STORED PAIR ACTUALLY VERIFIES — bullet 5's sent half, and nothing else checks it", async () => {
    /**
     * ⚠️ THE ONE ASSERTION THAT CAN CATCH A WRONG PUBKEY INDEX, AND IT DID NOT EXIST.
     *
     * Bullet 5's sent half stores our own signature on the transcript row so a third party can prove
     * we wrote it. `sendContent` builds that pair by decoding the sender pubkey out of
     * `structure1_cbor` at **index 2** and pairing it with `sender_signature`.
     *
     * Review pass 1 found that BOTH halves of that work shipped — mine and the call sites — with
     * **zero execution of the path**. The existing authorship tests call `recordTranscriptMessage`
     * directly with hand-built bytes (`fill(0x7e)`, `fill(0x5a)`), so `decode()` never runs and no
     * `verify()` is ever called against a stored pair anywhere in the repo. **A wrong index, a wrong
     * key, or a mismatched pair would all produce a row that LOOKS checkable and fails** — silently,
     * because nothing in production reads those columns back yet either.
     *
     * This closes it with real crypto and no fabricated values: submit through a real
     * `AgentRelayClient`, take the bytes and signature it actually produced, decode the pubkey the
     * way `sendContent` does, and **verify the signature against it**. If index 2 is not the sender
     * pubkey, `verify` returns false and this goes red. That single assertion covers the index, the
     * pairing, and whether the signing key matches the stored key — the three ways this can be
     * quietly wrong.
     */
    const { client, relay, sid } = await connectedClient();
    const contentHash = new Uint8Array(32).fill(0x11);

    const submit = client.submitMessageHash(relay.node, sid, contentHash, LEAF_KIND_MSG);
    await authenticate(relay);
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    const res = await submit;
    expect(res.ok, "the submit must succeed or there is no pair to check").toBe(true);
    if (!res.ok) return;

    expect(res.structure1_cbor, "the signed bytes must come back").toBeTruthy();
    expect(res.sender_signature, "the signature must come back — it was never handed back before bullet 5").toBeTruthy();
    expect(res.sender_signature!.length, "an Ed25519 signature is 64 bytes; a short one would store an uncheckable BLOB").toBe(64);

    // EXACTLY what sendContent does — index 2 of Structure 1.
    const s1 = decode(res.structure1_cbor!) as unknown[];
    const pk = s1[2];
    expect(pk instanceof Uint8Array, "index 2 of Structure 1 must be the sender pubkey").toBe(true);
    expect((pk as Uint8Array).length, "an Ed25519 public key is 32 bytes").toBe(32);

    /**
     * ⚠️ THE ASSERTION ITSELF. This is what a third party does with the row, and it is the only
     * thing that distinguishes a real proof from 96 bytes that merely look like one.
     */
    expect(
      verify(pk as Uint8Array, res.structure1_cbor!, res.sender_signature!),
      "the stored pubkey does NOT verify the stored signature over the signed bytes — a sent transcript row " +
        "built from these would look checkable to an auditor and fail. Suspect the Structure 1 index or the " +
        "pubkey source before anything else.",
    ).toBe(true);
    client.close();
  });

  it("★★ AN UNBOUND OR NON-PAYLOAD CTRL LEAF IS REFUSED LOCALLY — pass 2, HIGH-1 and MEDIUM-1", async () => {
    /**
     * ⚠️ TWO PROPERTIES THE PARAMETER'S OWN JUSTIFICATION RESTS ON, AND NEITHER WAS ENFORCED.
     *
     * The justification for letting the client hand the relay leaf content at all is that a SEAL
     * payload is `[session_id, final_root, close_timestamp, "PENDING"]` — four values the relay
     * already knows. The code checked `leafKind === CTRL` and nothing else, so:
     *
     *   1. **Arbitrary bytes on a ctrl leaf were transmitted.** Four kilobytes of the operator's
     *      text would have crossed the wire to the relay and been refused only there — after the
     *      disclosure the local guard exists to prevent. The relay learned this exact lesson at its
     *      own review one file over; I wrote the weaker version anyway.
     *   2. **A payload that does not hash to the signed `content_hash` was transmitted.** This is
     *      the worse one. The directory reports it as `seal_payload_unbound`, whose guidance reads
     *      *"the relay is the only party on that path — treat this as relay tampering."* A
     *      client-side derivation slip would be published as a named accusation against a relay
     *      operator who did nothing.
     *
     * Both are refused here now, before the frame is built.
     */
    const { client, relay, sid } = await connectedClient();
    const { payload, contentHash } = sealFor(sid);

    // Authenticated first — a client that cannot send refuses everything for free, and both
    // assertions below would then be measuring the handshake. (Same trap as the two tests above.)
    const warmup = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(7), LEAF_KIND_MSG);
    await authenticate(relay);
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    expect((await warmup).ok, "the client must be able to send, or the refusals below prove nothing").toBe(true);
    const framesBefore = relay.sentFrames.filter((f) => f["type"] === "hash_submit").length;

    // (1) A real payload, but paired with someone else's hash — the substituted-argument shape that
    //     the required-parameter change could not catch.
    const unbound = await client.submitLeaf(relay.node, sid, new Uint8Array(32).fill(0xab), LEAF_KIND_CTRL, payload);
    expect(unbound.ok, "a payload that does not hash to the signed content_hash must not be sent").toBe(false);
    expect(
      unbound.ok === false ? unbound.reason : "",
      "and it must name the CLIENT's mistake — the directory would name the relay's innocence as guilt",
    ).toBe("seal_payload_unbound");

    // (2) Bytes that hash correctly but are not a SEAL payload at all — the operator's content
    //     wearing a ctrl leaf. Hashed here so the refusal is unambiguously about the CONTENT,
    //     not about the binding checked above.
    const operatorText = new TextEncoder().encode("the merger price is 4.2m, do not forward this");
    const textHash = new Uint8Array(
      createHash("sha256").update(new Uint8Array([LEAF_KIND_CTRL])).update(operatorText).digest(),
    );
    const notAPayload = await client.submitLeaf(relay.node, sid, textHash, LEAF_KIND_CTRL, operatorText);
    expect(notAPayload.ok, "arbitrary bytes on a ctrl leaf are still the operator's content").toBe(false);
    expect(notAPayload.ok === false ? notAPayload.reason : "").toBe("seal_payload_invalid");

    // (3) A well-formed payload for a DIFFERENT session — a replay, caught before the wire.
    const otherSession = sealFor(new Uint8Array(16).fill(0x99));
    const replay = await client.submitLeaf(relay.node, sid, otherSession.contentHash, LEAF_KIND_CTRL, otherSession.payload);
    expect(replay.ok, "a payload naming another session must not be sent for this one").toBe(false);
    expect(replay.ok === false ? replay.reason : "").toBe("seal_payload_invalid");

    expect(
      relay.sentFrames.filter((f) => f["type"] === "hash_submit").length - framesBefore,
      "NOTHING may go out — the operator's text in case (2) is the whole reason this guard is local",
    ).toBe(0);
    client.close();

    void contentHash;
  });

  it("★★ CONTENT ON A NON-CTRL LEAF IS REFUSED LOCALLY — before the operator's words leave the machine", async () => {
    /**
     * ⚠️ THE COUNTERBALANCE, ENFORCED.
     *
     * The relay refuses this too. That is not enough on its own: by the time the relay refuses, the
     * content has already crossed the wire to the party that must not have it, AND the refusal voids
     * the whole frame — so a client bug here would destroy the operator's message rather than
     * protect it. The local refusal is what makes the relay's a second line rather than the only one.
     *
     * Asserted as "no frame went out", not merely "returned not-ok": returning an error while still
     * sending would satisfy a weaker assertion and disclose the content anyway.
     *
     * ⚠️ THE CLIENT IS AUTHENTICATED FIRST, AND THAT LINE IS THE TEST.
     *
     * Without it this passed for the wrong reason. I found it by running the mutant: with the guard
     * disabled, the refusal came back as `relay_unavailable` after a 5-second auth timeout, and
     * "nothing went out" was still true — because an unauthenticated client cannot send ANYTHING.
     * The assertion was measuring the handshake, not the guard. A test whose subject never gets the
     * chance to fail proves nothing about it.
     */
    const { client, relay, sid } = await connectedClient();
    const { payload } = sealFor(sid);

    // A real message submit that SUCCEEDS — the client is now authenticated with a live stream, so
    // a frame would genuinely go out if the guard let one.
    const warmup = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(7), LEAF_KIND_MSG);
    await authenticate(relay);
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    expect((await warmup).ok, "the client must be able to send, or the refusals below prove nothing").toBe(true);
    const framesBefore = relay.sentFrames.filter((f) => f["type"] === "hash_submit").length;

    const msgResult = await client.submitLeaf(relay.node, sid, new Uint8Array(32).fill(1), LEAF_KIND_MSG, payload);
    expect(msgResult.ok, "content on a message leaf must be refused").toBe(false);
    expect(
      msgResult.ok === false ? msgResult.reason : "",
      "named for the actual cause, so the log does not read as a relay outage",
    ).toBe("content_not_permitted_for_leaf_kind");

    const docResult = await client.submitLeaf(relay.node, sid, new Uint8Array(32).fill(1), LEAF_KIND_DOC, payload);
    expect(docResult.ok, "and a document leaf's content is the operator's document").toBe(false);

    expect(
      relay.sentFrames.filter((f) => f["type"] === "hash_submit").length - framesBefore,
      "NOTHING may go out — a refusal after transmission has already disclosed the content",
    ).toBe(0);
    client.close();
  });

  it("★★ A CTRL SUBMIT WITH NO PAYLOAD IS REFUSED — the silent downgrade is what let this hide", async () => {
    /**
     * ⚠️ THE DIRECTION THAT STOPS THIS RECURRING, and it is deliberately strict.
     *
     * The defect was not a wrong value. It was a dropped argument that degraded silently: the seal
     * still succeeded, the relay still acked, the receipt was still issued, and three hops later the
     * directory reported `not_carried` and blamed the relay's build version. Four reviewed legs
     * shipped over that.
     *
     * A ctrl leaf on this path is a SEAL leaf and always has a payload. Making its absence a named
     * local refusal means the next dropped argument breaks the seal on the machine that dropped it,
     * with the cause in the reason string, instead of becoming a false claim about someone else's
     * deployment.
     *
     * ⚠️ The cost is stated rather than hidden: this can refuse a close. That is the trade — a loud
     * failure an operator can act on, against a quiet one that silently removes the guard the whole
     * milestone was spent building. If a non-seal ctrl leaf is ever added, it must decide explicitly
     * what it carries; it will find out immediately, which is the point.
     *
     * Authenticated first, for the same reason as the test above: with the guard disabled the mutant
     * returned `relay_unavailable` after an auth timeout, and "nothing went out" held because the
     * client could not send at all. Both halves of that assertion were measuring the handshake.
     */
    const { client, relay, sid } = await connectedClient();
    const { contentHash } = sealFor(sid);

    const warmup = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(7), LEAF_KIND_MSG);
    await authenticate(relay);
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    expect((await warmup).ok, "the client must be able to send, or the refusal below proves nothing").toBe(true);
    const framesBefore = relay.sentFrames.filter((f) => f["type"] === "hash_submit").length;

    const result = await client.submitLeaf(relay.node, sid, contentHash, LEAF_KIND_CTRL, null);
    expect(result.ok, "a SEAL leaf with no payload must not be sent as if it were fine").toBe(false);
    expect(
      result.ok === false ? result.reason : "",
      "and it must name ITSELF — `not_carried` three hops later blames the wrong machine",
    ).toBe("seal_payload_not_carried");
    expect(
      relay.sentFrames.filter((f) => f["type"] === "hash_submit").length - framesBefore,
      "and no half-formed seal leaf reaches the relay's log",
    ).toBe(0);
    client.close();
  });
});
