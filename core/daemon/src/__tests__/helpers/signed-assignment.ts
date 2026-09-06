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

import { generateKeypair, buildKeyBindingTbs, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { buildSessionEstablishmentTbs, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";

/**
 * A REAL Ed25519 identity for a fixture — 038-KEYBIND.
 *
 * ⚠️ FIXTURES USED TO USE MADE-UP PUBKEYS (`"ee".repeat(32)`), because nothing ever verified a
 * signature BY the initiator. The key binding does: the assignment now carries a signature under
 * participant_a's own K_local naming its group key, and a responder refuses without it. A made-up
 * 32-byte value has no private half, so no such signature can exist for it — a fixture that keeps
 * one is describing a session production would (correctly) refuse.
 *
 * `pubkeyHex` is read synchronously off `toJSON()` so this is callable from module scope and from
 * inside a `describe` body, where `await` is not available.
 */
export interface FixtureIdentity {
  kp: KeyProvider;
  pubkey: Uint8Array;
  pubkeyHex: string;
}

/**
 * The fixture identity table — pubkey hex → the provider that can sign for it.
 *
 * ─── Why a table instead of threading the keypair to every call ────────────────────────────────
 *
 * Fixtures build their assignments through per-file `assignmentFrame(hexString, …)` helpers with a
 * dozen call sites each. Threading a keypair through all of them would be ~150 lines of mechanical
 * churn in files this order has no business rewriting, and every one of those lines is a chance to
 * change a test's meaning by accident.
 *
 * ─── Why it is not hidden state ────────────────────────────────────────────────────────────────
 *
 * It has exactly one writer (`fixtureIdentity`), it is never read except to find a signer, and a
 * MISS THROWS with the fix in the message. A fixture that keeps an invented pubkey fails at build
 * time and says why — it cannot silently produce an unsigned assignment, which is the one outcome
 * that would matter.
 */
const FIXTURE_KEYS = new Map<string, KeyProvider>();

export function fixtureIdentity(): FixtureIdentity {
  const kp = generateKeypair();
  const pubkeyHex = kp.toJSON()["publicKey"]!;
  registerFixtureSigner(pubkeyHex, kp);
  return { kp, pubkey: new Uint8Array(Buffer.from(pubkeyHex, "hex")), pubkeyHex };
}

/**
 * Register a key a fixture already owns — for the harnesses that create a REAL agent (a
 * `FileKeyProvider` under `agents/<name>/key`) and then inject an assignment naming it. Those
 * identities are not minted by `fixtureIdentity`, but their private half IS in hand at creation
 * time, which is all the binding needs.
 */
export function registerFixtureSigner(pubkeyHex: string, kp: KeyProvider): void {
  FIXTURE_KEYS.set(pubkeyHex.toLowerCase(), kp);
}

export interface SignedAssignmentOpts {
  sessionId: Uint8Array;
  /**
   * participant_a — the INITIATOR's K_local identity pubkey. It MUST come from `fixtureIdentity()`
   * (directly, or as the `pubkeyHex` a test stores in a constant): 038-KEYBIND makes the assignment
   * carry a signature by this identity, so the fixture needs its private half.
   */
  initiatorPubkey: Uint8Array;
  /** participant_b — the RESPONDER's K_local identity pubkey. */
  responderPubkey: Uint8Array;
  initiatorSessionPeerId: string;
  counterpartySessionPeerId?: string;
  sessionTimestamp?: number;
  /** Sign with this key instead of a fresh one — for pinned-mode tests. */
  signWith?: ReturnType<typeof generateKeypair>;
  /**
   * 017-TBS. Supply BOTH to sign and emit the 12-field layout; omit both for the 10-field one.
   * Defaulting them here would be wrong: an assignment that omits them is what an older directory
   * sends, and the existing fixtures are entitled to keep testing that shape.
   */
  highStakes?: boolean;
  priorRelayId?: string;
  /** 038-KEYBIND: send NO key binding — the absent-proof refusal. */
  omitKeyBinding?: boolean;
  /** 038-KEYBIND: sign the binding with a DIFFERENT key — the failed-proof refusal. */
  forgeKeyBinding?: boolean;
  /** 038-KEYBIND: send NO counterparty group key / binding — the initiator-side absent refusal. */
  omitCounterpartyBinding?: boolean;
  /** 038-KEYBIND: sign the counterparty binding with a DIFFERENT key — the initiator-side failure. */
  forgeCounterpartyBinding?: boolean;
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
  const initiatorPubkey = opts.initiatorPubkey;
  const genesis = computeGenesisPrevRoot(initiatorPubkey, opts.responderPubkey, opts.sessionId, ts);
  const tbs = buildSessionEstablishmentTbs(
    opts.sessionId,
    initiatorPubkey,
    opts.responderPubkey,
    genesis,
    ts,
    opts.initiatorSessionPeerId,
    initiatorAddrs,
    counterpartyPeerId,
    counterpartyAddrs,
    "relay",
    // Passed through as-is, INCLUDING undefined: the builder picks its layout on arity, so
    // forwarding a default here would silently sign 12 fields for a fixture asking for 10.
    opts.highStakes,
    opts.priorRelayId,
  );

  // The FROST context framing the directory signs under: context bytes, a 0x00 separator, then TBS.
  const enc = new TextEncoder().encode(CONTEXT_SESSION_ESTABLISHMENT);
  const framed = new Uint8Array(enc.length + 1 + tbs.length);
  framed.set(enc, 0);
  framed[enc.length] = 0x00;
  framed.set(tbs, enc.length + 1);

  /**
   * 038-KEYBIND. The initiator's identity key signs for the group key the assignment names as its
   * signer, so the responder can PLACE that key rather than taking the frame's word for it.
   *
   * A fixture testing REFUSAL omits or corrupts this (`omitKeyBinding` / `forgeKeyBinding`) rather
   * than supplying noise, for the reason in the header: a tampered proof tests that the binding
   * holds, whereas garbage only tests that garbage is rejected.
   */
  const initiatorHex = Buffer.from(initiatorPubkey).toString("hex").toLowerCase();
  const initiatorKp = FIXTURE_KEYS.get(initiatorHex);
  if (!initiatorKp) {
    throw new Error(
      `signed-assignment: no private key for participant_a ${initiatorHex.slice(0, 16)}… — ` +
        "038-KEYBIND requires the initiator to SIGN a key binding, so an invented pubkey cannot be " +
        "used here. Build the identity with fixtureIdentity() and use its .pubkeyHex / .pubkey.",
    );
  }
  const bindingSigner = opts.forgeKeyBinding ? generateKeypair() : initiatorKp;
  const keyBinding = await bindingSigner.sign(buildKeyBindingTbs(initiatorPubkey, signerPubkey));

  /**
   * 038-KEYBIND — the OTHER direction, which only the INITIATOR path reads.
   *
   * The responder's own group key rides here with a binding signed by participant_b's K_local, so
   * an initiator learns it and a responder-first seal verifies locally. Emitted only when this
   * fixture holds the responder's private half: responder-side fixtures pass a raw `responderPubkey`
   * and never look at these fields, and inventing an unsignable pair for them would fail the build
   * for a frame nothing reads.
   */
  const responderKp = FIXTURE_KEYS.get(Buffer.from(opts.responderPubkey).toString("hex").toLowerCase());
  const responderPrimary = new Uint8Array(32).fill(0x5b);
  const counterpartyBinding = responderKp
    ? await (opts.forgeCounterpartyBinding ? generateKeypair() : responderKp).sign(
        buildKeyBindingTbs(opts.responderPubkey, responderPrimary),
      )
    : undefined;

  return {
    signerPubkeyHex: Buffer.from(signerPubkey).toString("hex"),
    frame: {
      type: "session_assignment",
      assignment: {
        session_id: opts.sessionId,
        participant_a: { pubkey: initiatorPubkey, peer_id: "12D3KooWA", multiaddrs: [] },
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
        // Only present when signed over — a frame carrying a field the TBS does not cover would
        // let the verifier rebuild a layout the signature was never taken over.
        ...(opts.highStakes !== undefined ? { high_stakes: opts.highStakes } : {}),
        ...(opts.priorRelayId !== undefined ? { prior_relay_id: opts.priorRelayId } : {}),
        // 038-KEYBIND. Omitted only when a fixture is deliberately testing the absent-binding
        // refusal — the production directory always sends it.
        ...(opts.omitKeyBinding ? {} : { participant_a_key_binding: keyBinding }),
        ...(counterpartyBinding && !opts.omitCounterpartyBinding
          ? {
              participant_b_primary_pubkey: responderPrimary,
              participant_b_key_binding: counterpartyBinding,
            }
          : {}),
      },
    },
  };
}
