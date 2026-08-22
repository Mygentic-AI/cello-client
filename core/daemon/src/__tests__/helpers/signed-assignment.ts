/**
 * A `session_assignment` frame that actually VERIFIES — for fixtures that inject one directly.
 *
 * ─── Why this exists ───────────────────────────────────────────────────────────────────────────
 *
 * `DOD-M15-RESPONDER-VERIFY-1` made the responder verify inbound assignments. Before it, the
 * responder logged `session.inbound.assignment.unverified` and proceeded, so every fixture that
 * injected an assignment could fill `directory_signature` with zeroes and be accepted.
 *
 * Those fixtures were not wrong to exist — they test contact whitelisting, doorbells, moniker
 * resolution, away-mode — none of which is about signatures. They were wrong to be *unverifiable*,
 * because that is precisely the property the production path had lost and nobody noticed.
 *
 * ─── What it does ──────────────────────────────────────────────────────────────────────────────
 *
 * Mints a keypair, recomputes the genesis prev-root exactly as the directory does, builds the
 * session-establishment TBS from the assignment's own contents, and signs it under the FROST
 * context. The result passes `verifyInboundAssignment` in its internal-consistency mode.
 *
 * `signerPubkey` is returned so a caller that wants the PINNED mode can seed the pin with it and
 * exercise the stronger check.
 *
 * ─── The thing to keep in mind when using it ───────────────────────────────────────────────────
 *
 * A fixture that needs to test REFUSAL should tamper AFTER signing — change a field the TBS covers
 * — rather than supplying a garbage signature. A garbage signature tests that noise is rejected; a
 * tampered field tests that the binding holds, which is the property that matters.
 */

import { generateKeypair, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
import { buildSessionEstablishmentTbs, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";

export interface SignedAssignmentOpts {
  sessionId: Uint8Array;
  /** participant_a — the INITIATOR's K_local identity pubkey. */
  initiatorPubkey: Uint8Array;
  /** participant_b — the RESPONDER's K_local identity pubkey. */
  responderPubkey: Uint8Array;
  initiatorSessionPeerId: string;
  counterpartySessionPeerId?: string;
  sessionTimestamp?: number;
  /** Sign with this key instead of a fresh one — for pinned-mode tests. */
  signWith?: ReturnType<typeof generateKeypair>;
}

export async function makeSignedAssignmentFrame(
  opts: SignedAssignmentOpts,
): Promise<{ frame: Record<string, unknown>; signerPubkeyHex: string }> {
  const signer = opts.signWith ?? generateKeypair();
  const signerPubkey = await signer.getPublicKey();
  const ts = opts.sessionTimestamp ?? 1_700_000_000_000;
  const initiatorAddrs = ["/ip4/127.0.0.1/tcp/3"];
  const counterpartyPeerId = opts.counterpartySessionPeerId ?? "12D3KooWReceiver";
  const counterpartyAddrs = ["/ip4/127.0.0.1/tcp/4"];

  // RECOMPUTED, exactly as both the directory and the verifier do: `genesis_prev_root` is not on
  // the wire, so a fixture that invented one would produce a frame that cannot verify anywhere.
  const genesis = computeGenesisPrevRoot(opts.initiatorPubkey, opts.responderPubkey, opts.sessionId, ts);
  const tbs = buildSessionEstablishmentTbs(
    opts.sessionId,
    opts.initiatorPubkey,
    opts.responderPubkey,
    genesis,
    ts,
    opts.initiatorSessionPeerId,
    initiatorAddrs,
    counterpartyPeerId,
    counterpartyAddrs,
    "relay",
  );

  // The FROST context framing the directory signs under: context bytes, a 0x00 separator, then TBS.
  const enc = new TextEncoder().encode(CONTEXT_SESSION_ESTABLISHMENT);
  const framed = new Uint8Array(enc.length + 1 + tbs.length);
  framed.set(enc, 0);
  framed[enc.length] = 0x00;
  framed.set(tbs, enc.length + 1);

  return {
    signerPubkeyHex: Buffer.from(signerPubkey).toString("hex"),
    frame: {
      type: "session_assignment",
      assignment: {
        session_id: opts.sessionId,
        participant_a: { pubkey: opts.initiatorPubkey, peer_id: "12D3KooWA", multiaddrs: [] },
        participant_b: { pubkey: opts.responderPubkey, peer_id: "12D3KooWB", multiaddrs: [] },
        relay_endpoint: { peer_id: "12D3KooWRelay", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] },
        directory_endpoint: { peer_id: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/2"] },
        session_timestamp: ts,
        directory_pubkey: new Uint8Array(32).fill(0xdd),
        directory_signature: await signer.sign(framed),
        signature_type: "frost",
        signer_pubkey: signerPubkey,
        initiator_session_peer_id: opts.initiatorSessionPeerId,
        initiator_session_addrs: initiatorAddrs,
        counterparty_session_peer_id: counterpartyPeerId,
        counterparty_session_addrs: counterpartyAddrs,
        transport_mode: "relay",
      },
    },
  };
}
