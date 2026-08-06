/**
 * DOD-DOC-DELIVERY-2 — the opener contract the delivery worker depends on.
 *
 * The worker calls into `cello_initiate_session`'s path with no IPC connection. Which key it hands
 * over is expressed in WIRE names inside `params`, and those names are not guessable: the negotiator
 * reads `target_pubkey`, falling back to `counterparty_pubkey`, and reads nothing else.
 *
 * A caller that passes any other name gets `invalid_target_pubkey` — an error whose guidance sends
 * whoever reads it to look at the PEER's key, when the bug is the caller's own field name. That is
 * what shipped: the sweep passed `{ pubkey }`, so the REUSE path (a session already open) worked and
 * the OPEN path never did. Delivery appeared to work in exactly the case a developer tests by hand,
 * and never in the case the feature exists for — a peer who came back online with no session up.
 *
 * The stub negotiator below applies the SAME rule the real one does (`outbound-sessions.ts`). If the
 * two ever drift this test stops meaning anything, so it asserts on the received params too.
 */

import { describe, it, expect } from "vitest";
import { registerInitiateSessionHandler } from "../initiate-session-handler.js";
import type { IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";
import type { SessionNegotiator } from "../transport-selector.js";
import type { IAutoNatService } from "@cello-protocol/transport";

const PEER = "ab".repeat(32);

function silentLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} } as unknown as Logger;
}

function newOpener() {
  const seen: Array<Record<string, unknown>> = [];
  // Mirrors outbound-sessions.ts:528-539 — the only two names the real negotiator reads.
  const negotiator = {
    negotiate: async (req: { params: Record<string, unknown> }) => {
      seen.push(req.params);
      const target =
        typeof req.params.target_pubkey === "string"
          ? req.params.target_pubkey
          : typeof req.params.counterparty_pubkey === "string"
            ? req.params.counterparty_pubkey
            : "";
      if (!/^[0-9a-fA-F]{64}$/.test(target)) {
        return {
          ok: false as const,
          reason: "invalid_target_pubkey",
          guidance: "cello_initiate_session requires 'target_pubkey' as the counterparty's 32-byte hex K_local public key.",
        };
      }
      // Enough to prove the params landed; the rest of the open path is covered elsewhere.
      return { ok: false as const, reason: "reached_negotiator", guidance: "" };
    },
  } as unknown as SessionNegotiator;

  const { openSessionFor, openSessionAs } = registerInitiateSessionHandler({
    handlers: new Map<string, IpcHandler>(),
    logger: silentLogger(),
    sessionNodeManager: {} as never,
    getConnState: () => undefined,
    resolveCurrentAgent: (_c, explicit) => explicit ?? null,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    resolvedSessionNegotiator: negotiator,
    transportSelector: {} as never,
    autoNatService: { getDialability: () => ({ dialable: false }) } as unknown as IAutoNatService,
    buildRelayConnectParams: async () => undefined,
    getRelayCircuitAddress: () => "",
  });
  return { openSessionFor, openSessionAs, seen };
}

describe("openSessionFor — a TypeScript name the caller cannot get wrong", () => {
  it("reaches the negotiator with the counterparty key under the name it reads", async () => {
    const o = newOpener();
    const res = await o.openSessionFor("agent-a", { targetPubkey: PEER });

    // Past the key check. Anything else here means the key never arrived.
    expect(res).toMatchObject({ reason: "reached_negotiator" });
    expect(o.seen[0]).toEqual({ target_pubkey: PEER });
  });

  it("REPRODUCES the defect the typed wrapper exists to prevent", async () => {
    const o = newOpener();
    // The exact object the delivery sweep shipped with. A valid key, under a name nothing reads.
    const res = await o.openSessionAs("agent-a", { pubkey: PEER });

    expect(res).toMatchObject({ reason: "invalid_target_pubkey" });
    // And this is why it was hard to see: the guidance is about the PEER's key, which is correct
    // for a human calling the MCP tool and misleading for an internal worker whose own field name
    // is the bug. `openSessionFor` makes the shape unrepresentable rather than better-worded.
    expect(String((res as { guidance?: string }).guidance)).toContain("target_pubkey");
  });
});
