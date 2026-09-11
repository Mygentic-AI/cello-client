/**
 * DOD-M15-TOKENRACE-1 — **THE BETTER THE CONNECTION, THE STALER THE CREDENTIAL.**
 *
 * ─── The defect, measured before it was explained ──────────────────────────────────────────────
 *
 * A relay refuses to talk to an agent at all without a directory-signed ONLINE TOKEN. Not only for
 * reservations: the relay's token gate has ONE call site and it sits on the general auth path, so
 * the same credential is required to send a message, to seal, and to deposit or pull parked mail.
 *
 * The directory mints one and puts it on `signaling_auth_ok` — the HANDSHAKE. It lives one hour.
 * The signaling manager's heartbeat (15 s ping, 15 s pong timeout) keeps the stream alive and
 * reconnects when it dies, and it works. **So a connection that stays healthy never handshakes
 * again, and never receives another token.** Everything that looks like health is working, which is
 * why this was invisible.
 *
 * Measured on a real daemon, 2026-09-07 to 2026-09-11: 186 token receipts, median gap 15 minutes,
 * **18 gaps longer than the one-hour lifetime**, worst case 8.4 hours — with ZERO signaling
 * disconnects inside that 8.4-hour window until its very end. The channel was healthy for all of it.
 *
 * What the operator sees: their agent has been idle, someone calls, and the agent cannot get a relay
 * slot. A caller behind a home router cannot reach them; with the IP-disclosure control on, the call
 * is refused outright. The agent most likely to hit it is the one that has been quiet longest, which
 * is exactly the agent somebody is about to call.
 *
 * ─── Why this test is about a WIRING LINE, and why that is the whole fix ───────────────────────
 *
 * `048-SWEEPTICK` already opens an AUTHENTICATED visiting connection to every other directory node
 * every five minutes, per online agent. The directory issues a token on that auth_ok unconditionally
 * — `#issueOnlineToken` is not gated on `visiting` and not gated on presence, only on the agent
 * having a profile at that node. A fresh credential has therefore been arriving every five minutes
 * all along, and `openVisitingConnection` never wired `onOnlineToken`, so it was parsed, logged and
 * dropped.
 *
 * No new frame, no directory change, no deploy ordering. One line.
 *
 * ⚠️ **AND THAT IS EXACTLY THE SHAPE 056-SLOTDEAD SPENT A DAY REMOVING**, so it is tested rather
 * than trusted. A credential refresh that rides an unrelated feature's timer is the same defect as
 * a mailbox drain that rode a receiver rebuild: it works until somebody changes the thing it rides
 * on, and then it stops with nothing saying so. This file is what makes removing the wiring red.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";

/**
 * The seam. `openVisitingConnection` builds its stream through `createSignalingConnect`, so
 * capturing that call captures the entire set of things this connection is wired to notice — which
 * is precisely what the defect was about: a callback that was never passed.
 */
const captured: Array<Record<string, unknown>> = [];
vi.mock("../signaling-connect.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../signaling-connect.js")>();
  return {
    ...actual,
    createSignalingConnect: (deps: Record<string, unknown>) => {
      captured.push(deps);
      return actual.createSignalingConnect(deps as unknown as Parameters<typeof actual.createSignalingConnect>[0]);
    },
  };
});

const { createOutboundSessions } = await import("../outbound-sessions.js");
type OutboundSessionDeps = import("../outbound-sessions.js").OutboundSessionDeps;
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

const AGENT = "alice";
const AGENT_PUBKEY = "bb".repeat(32);
const TOKEN = new Uint8Array([0xca, 0xfe, 0xba, 0xbe]);

/** Only what `openVisitingConnection` itself touches — everything else stays unbuilt on purpose. */
function makeOutbound(): {
  open: (agentName: string, endpoint: unknown, correlationId: string, nodeId: string) => unknown;
  tokensStored: Array<{ agentName: string; token: Uint8Array }>;
} {
  const tokensStored: Array<{ agentName: string; token: Uint8Array }> = [];
  const sessionNodeManager = {
    setDirectoryOnlineToken(agentName: string, token: Uint8Array) {
      tokensStored.push({ agentName, token });
    },
    verifyCertifiedRoot: () => true,
    getStandingReceiverInfo: () => null,
  };
  const outbound = createOutboundSessions({
    logger: silent,
    sessionNodeManager,
    getKeyProvider: () => generateKeypair(),
    getPersistence: () => ({
      async loadRegistrationState() {
        return { agentId: "agent-1", primaryPubkey: AGENT_PUBKEY, mlDsaPubkey: "", registeredAt: 0, status: "registered" };
      },
      async listTrustSignalsForPresentation() { return []; },
      async loadOutboundMoniker() { return null; },
    }),
    getAgentSignaling: () => ({ signaling: { status: "connected", async sendRaw() { return { ok: true as const }; }, registerInboundHandler: () => () => {} }, getNode: () => null }),
    waitForSignalingConnected: async () => true,
    getFailoverEndpoint: async () => null,
    resolveConsortiumRoster: async () => null,
    registerSealListeners: () => () => {},
    registerPickupListener: () => ({ settle: async () => {} }),
    getManifestVersion: () => 1,
    loadedAgents: [{ name: AGENT, pubkey: AGENT_PUBKEY }],
  } as unknown as OutboundSessionDeps);
  return {
    open: (outbound as unknown as { openVisitingConnection: (a: string, e: unknown, c: string, n: string) => unknown }).openVisitingConnection,
    tokensStored,
  };
}

describe("DOD-M15-TOKENRACE-1: the visiting connection refreshes the relay credential", () => {
  beforeEach(() => { captured.length = 0; });

  it("★★★ a visiting connection's auth_ok STORES the credential — the fix, and the revert test is deleting the wiring", async () => {
    const h = makeOutbound();
    h.open(AGENT, { peerId: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] }, "corr-1", "gcp-use1");

    expect(captured.length, "the visiting connection must build a signaling connect").toBeGreaterThan(0);
    const deps = captured[captured.length - 1]!;

    /**
     * ⚠️ ASSERTED BY CALLING IT, NOT BY ITS PRESENCE. A test that only checked the key existed would
     * pass for a callback wired to the wrong agent, or to nothing at all. Invoking it is what proves
     * the token reaches the store the relay clients read.
     */
    const onOnlineToken = deps["onOnlineToken"];
    expect(
      typeof onOnlineToken,
      "the visiting connection must notice the credential its own handshake was handed. Without " +
        "this the daemon authenticates to every directory every five minutes and throws the fresh " +
        "credential away, and the agent's relay access expires while its connection is perfectly " +
        "healthy — measured at 8.4 hours against a one-hour lifetime",
    ).toBe("function");

    (onOnlineToken as (t: Uint8Array) => void)(TOKEN);
    expect(h.tokensStored, "the credential must reach the store every relay client reads").toEqual([
      { agentName: AGENT, token: TOKEN },
    ]);
  });

  it("the visiting connection is still VISITING — a refresh must not mark the agent present at three nodes", () => {
    const h = makeOutbound();
    h.open(AGENT, { peerId: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] }, "corr-2", "gcp-use1");

    const deps = captured[captured.length - 1]!;
    expect(
      deps["visiting"],
      "this connection exists to sweep and now also to refresh; if it ever wrote presence, a " +
        "transient stream would claim the agent is reachable at a node it is not listening on",
    ).toBe(true);
  });

  it("the credential is stored against the agent that owns the connection, not a global", () => {
    const h = makeOutbound();
    h.open(AGENT, { peerId: "12D3KooWDir", multiaddrs: ["/ip4/127.0.0.1/tcp/1"] }, "corr-3", "gcp-use1");
    const deps = captured[captured.length - 1]!;
    (deps["onOnlineToken"] as (t: Uint8Array) => void)(TOKEN);

    // One connection per agent is the invariant the whole channel design rests on. A token stored
    // under the wrong name would hand one agent another's relay credential, which the relay refuses
    // as `online_token_pubkey_mismatch` — an agent locked out by its own daemon.
    expect(h.tokensStored.map((t) => t.agentName)).toEqual([AGENT]);
  });
});
