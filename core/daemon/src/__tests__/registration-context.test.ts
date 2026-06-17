/**
 * CELLO-M7-REGISTRATION — DaemonRegistrationContext inbound routing (step c part 2)
 *
 * Pins the signaling bridge: the single registered inbound handler routes the
 * three registration reply frames to the correct armed resolver, ignores
 * unrelated frames (leaving them for other inbound handlers), and delegates
 * status/send to the underlying SignalingManager seam.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { DaemonRegistrationContext, type SignalingSeam } from "../registration-context.js";
import type { Logger } from "../types.js";
import type { KeyProvider } from "@cello-protocol/crypto";

function makeSeam(status: "connected" | "reconnecting" | "lost" = "connected") {
  let handler: ((frame: Record<string, unknown>) => void) | null = null;
  const sent: unknown[] = [];
  const seam: SignalingSeam = {
    status,
    async sendRaw(frame: unknown) {
      sent.push(frame);
      return { ok: true };
    },
    registerInboundHandler(h) {
      handler = h;
      return () => {
        handler = null;
      };
    },
  };
  return {
    seam,
    feed: (f: Record<string, unknown>) => handler?.(f),
    isRegistered: () => handler !== null,
    sent,
  };
}

const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const stubKeyProvider = { async getPublicKey() { return new Uint8Array(32); } } as unknown as KeyProvider;

function makeCtx(status: "connected" | "reconnecting" | "lost" = "connected") {
  const s = makeSeam(status);
  const ctx = new DaemonRegistrationContext({
    signaling: s.seam,
    getDirectoryNode: () => null,
    getDirectoryEndpoint: () => ({ peer_id: "dir", multiaddrs: ["/ip4/1.2.3.4"] }),
    keyProvider: stubKeyProvider,
    persistence: null,
    logger: noopLogger,
  });
  return { ctx, ...s };
}

describe("DaemonRegistrationContext routing", () => {
  let h: ReturnType<typeof makeCtx>;
  beforeEach(() => { h = makeCtx(); });

  it("registers exactly one inbound handler on construction", () => {
    expect(h.isRegistered()).toBe(true);
  });

  it("routes a dkg_ready frame to the armed dkg-ready resolver and clears it", () => {
    let received: Record<string, unknown> | null = null;
    h.ctx.setPendingDkgReadyResolve((f) => { received = f; });
    h.feed({ type: "dkg_ready", epochId: "e1", threshold: 2, participants: 1 });
    expect(received).toEqual({ type: "dkg_ready", epochId: "e1", threshold: 2, participants: 1 });
    // cleared: a second dkg_ready must not re-fire the same resolver
    let secondReceived = false;
    h.ctx.setPendingDkgReadyResolve(() => { secondReceived = true; });
    h.feed({ type: "register_success", agent_id: "a", primary_pubkey: "p" });
    expect(secondReceived).toBe(false);
  });

  it("routes register_success to the armed register resolver", () => {
    let received: Record<string, unknown> | null = null;
    h.ctx.setPendingRegisterResolve((f) => { received = f; });
    h.feed({ type: "register_success", agent_id: "a1", primary_pubkey: "pp" });
    expect(received).toMatchObject({ type: "register_success", agent_id: "a1" });
  });

  it("routes register_error to the dkg-ready stage when it is the one waiting", () => {
    let received: Record<string, unknown> | null = null;
    h.ctx.setPendingDkgReadyResolve((f) => { received = f; });
    h.feed({ type: "register_error", reason: "already_registered", agent_id: "a", primary_pubkey: "p" });
    expect(received).toMatchObject({ type: "register_error", reason: "already_registered" });
  });

  it("routes register_error to the register stage when that is the one waiting", () => {
    let received: Record<string, unknown> | null = null;
    h.ctx.setPendingRegisterResolve((f) => { received = f; });
    h.feed({ type: "register_error", reason: "internal_error" });
    expect(received).toMatchObject({ type: "register_error", reason: "internal_error" });
  });

  it("ignores unrelated frames (leaves them for other inbound handlers)", () => {
    let fired = false;
    h.ctx.setPendingDkgReadyResolve(() => { fired = true; });
    h.feed({ type: "seal_interrupted_ack", sessionId: "s1" });
    h.feed({ type: "manifest_update" });
    h.feed({ notAFrameType: true });
    expect(fired).toBe(false);
  });

  it("reflects signaling status via isSignalingConnected()", () => {
    expect(makeCtx("connected").ctx.isSignalingConnected()).toBe(true);
    expect(makeCtx("reconnecting").ctx.isSignalingConnected()).toBe(false);
    expect(makeCtx("lost").ctx.isSignalingConnected()).toBe(false);
  });

  it("delegates sendSignalingFrame to the seam's sendRaw", async () => {
    const result = await h.ctx.sendSignalingFrame({ type: "register_request", k_local_pubkey: "k" });
    expect(result.ok).toBe(true);
    expect(h.sent).toEqual([{ type: "register_request", k_local_pubkey: "k" }]);
  });

  it("dispose() unregisters the inbound handler", () => {
    expect(h.isRegistered()).toBe(true);
    h.ctx.dispose();
    expect(h.isRegistered()).toBe(false);
  });
});
