/**
 * CELLO-M7-TRANSPORT-001 — autonat.test.ts
 *
 * ─── Specification (Phase S) ──────────────────────────────────────────────────
 * Understanding of the ACs/SIs exercised here:
 *
 * AC-001 — A standing-receiver node's libp2p config includes the AutoNAT client
 *   service (protocol /libp2p/autonat/1.0.0). The injected IAutoNatService stub
 *   exposes the directory-node prober set, which must be non-empty and not
 *   hardcoded (it is whatever was injected).
 * AC-002 — A session node also includes AutoNAT, AND includes dcutr (the
 *   relay-fallback hole-punch upgrade). DOD-NAT-REACHABILITY-1: the standing
 *   receiver includes dcutr too — the inbound peer initiates the upgrade, so the
 *   original "receiver omits dcutr" spec guaranteed the punch never started.
 * AC-003 — (CELLO_E2E_LIVE) real AutoNAT probe confirms dialable:true with a
 *   non-null publicAddr. Skipped without CELLO_E2E_LIVE (real network required).
 * AC-016 — default createNode (no nodeType) keeps AutoNAT and dcutr — no
 *   regression for directory/relay/client callers.
 * SI-002 — probers are exclusively the directory nodes in the active manifest. A
 *   non-manifest peer is never part of getProbers(), so a rogue dial-back
 *   responder cannot be counted toward dialability.
 *
 * AutoNAT protocol version note: AC-011 references /libp2p/autonat/2.0.0; CELLO
 * uses AutoNAT v1 (/libp2p/autonat/1.0.0) to stay aligned with the libp2p v3.0.x
 * service stack. Responder semantics are identical.
 */

import {
  setupV3Tests,
  createTestScope,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@claude-flow/testing";
import { generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "../node.js";
import { AUTONAT_PROTOCOL_ID } from "../protocols.js";
import {
  LocalAutoNatStub,
  DEFAULT_DIALABILITY,
  type Dialability,
} from "../autonat.js";

setupV3Tests();

const DCUTR_PROTOCOL_ID = "/libp2p/dcutr";

function keyProvider() {
  return generateKeypair();
}

// ─── AC-001: standing receiver includes AutoNAT client ───────────────────────

// M12: a CLIENT node no longer advertises the AutoNAT protocol. The responder half answers a
// dial-back by calling openConnection(peer) -- which RETURNS AN ALREADY-OPEN CONNECTION -- and then
// closes it, tearing down whatever else that connection carried (directory signaling, mid-DKG).
// The PROBER half is untouched: it opens OUTBOUND streams and advertises nothing, so dialability
// still works. `getProtocols()` reflects the inbound HANDLER, i.e. exactly the half that is gone.
describe("AC-001: standing receiver node has AutoNAT client + prober set", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("started standing-receiver node does NOT advertise the AutoNAT responder", async () => {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "standing_receiver",
    });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    expect(node.getProtocols()).not.toContain(AUTONAT_PROTOCOL_ID);
  });

  it("the injected IAutoNatService prober set is the directory multiaddrs (non-empty, not hardcoded)", () => {
    const directoryAddrs = [
      "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWDirA",
      "/ip4/203.0.113.20/tcp/4001/p2p/12D3KooWDirB",
    ];
    const autonat = new LocalAutoNatStub({ probers: directoryAddrs });
    expect(autonat.getProbers()).toEqual(directoryAddrs);
    expect(autonat.getProbers().length).toBeGreaterThan(0);
  });
});

// ─── AC-002: session node AND standing receiver both have AutoNAT + dcutr ─────
//
// DOD-NAT-REACHABILITY-1 SUPERSEDES the original AC-002: the old spec omitted
// dcutr from standing receivers on the reasoning "a receiver doesn't upgrade
// connections". That was backwards — @libp2p/dcutr's INBOUND peer initiates the
// hole-punch upgrade, and the standing receiver is the inbound side of every
// relayed connection. Omitting it guaranteed the punch could never start.

describe("AC-002 (superseded by DOD-NAT-REACHABILITY-1): both client node types carry AutoNAT + dcutr", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("session node keeps dcutr and drops the AutoNAT responder", async () => {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
    });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    const protocols = node.getProtocols();
    expect(protocols).not.toContain(AUTONAT_PROTOCOL_ID);
    // dcutr MUST survive -- it is a separate service and the hole-punch depends on it.
    expect(protocols).toContain(DCUTR_PROTOCOL_ID);
  });

  it("standing receiver keeps dcutr — it is the punch initiator — and drops the responder", async () => {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "standing_receiver",
    });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    const protocols = node.getProtocols();
    expect(protocols).not.toContain(AUTONAT_PROTOCOL_ID);
    expect(protocols).toContain(DCUTR_PROTOCOL_ID);
  });
});

// ─── M12: the autonatResponder opt-out, in BOTH directions ───────────────────
//
// nodeType is NOT a sufficient discriminator and this is the regression guard for that. The
// directory-SIGNALING node is a long-lived client that deliberately leaves nodeType UNSET, so a
// nodeType-only rule left the responder enabled on exactly the connection it destroys. The first
// attempt at this fix built, linted, and still failed for that reason.
describe("M12: autonatResponder opt-out overrides the nodeType default", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("a node with NO nodeType drops the responder when explicitly opted out", async () => {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      autonatResponder: { enabled: false },
    });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    expect(node.getProtocols()).not.toContain(AUTONAT_PROTOCOL_ID);
  });

  it("a client node KEEPS the responder when explicitly opted in", async () => {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "session",
      autonatResponder: { enabled: true },
    });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    // Proves the removal is driven by the OPTION, not by an unconditional unhandle() that would
    // strip the responder from directories and relays too.
    expect(node.getProtocols()).toContain(AUTONAT_PROTOCOL_ID);
  });
});

// ─── AC-016: default (no nodeType) keeps AutoNAT + dcutr (no regression) ──────

describe("AC-016: default node (no nodeType) keeps AutoNAT and dcutr", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("a default service node advertises both AutoNAT and dcutr", async () => {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
    });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    const protocols = node.getProtocols();
    expect(protocols).toContain(AUTONAT_PROTOCOL_ID);
    expect(protocols).toContain(DCUTR_PROTOCOL_ID);
  });
});

// ─── Dialability observable on the node ──────────────────────────────────────

describe("dialability observable: loopback node defaults to not-dialable", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("a loopback-only node reports { dialable:false, publicAddr:null } (no public addr)", async () => {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      nodeType: "standing_receiver",
    });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    const d = node.getDialability();
    expect(d.dialable).toBe(false);
    expect(d.publicAddr).toBeNull();
  });

  it("getDialability returns the conservative default before any probe", async () => {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
    });
    // Not started — no probe has run.
    expect(node.getDialability()).toEqual(DEFAULT_DIALABILITY);
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });
  });

  // ─── I5: a CONFIGURED public address is NOT proof of dialability ────────────
  // A node that is bound to / announces a public IP but is actually behind a
  // firewall must NOT report dialable:true. Dialability comes from AutoNAT
  // dial-back confirmation (an observed address), never from configuration.
  it("a node announcing a configured public IP still reports NOT dialable (no AutoNAT confirmation)", async () => {
    const node = await createNode({
      keyProvider: keyProvider(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      // Configured public announce address — but nothing confirmed it via dial-back.
      announceAddresses: ["/ip4/203.0.113.250/tcp/4001"],
      nodeType: "standing_receiver",
    });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    const d = node.getDialability();
    // The configured public host is excluded from the dialability derivation, so a
    // firewalled-but-public-announced node correctly reports not dialable.
    expect(d.dialable).toBe(false);
    expect(d.publicAddr).toBeNull();
  });
});

// ─── LocalAutoNatStub: configurable values + observe ─────────────────────────

describe("AC-009: LocalAutoNatStub returns configurable values and notifies observers", () => {
  it("defaults to not-dialable", () => {
    const stub = new LocalAutoNatStub();
    expect(stub.getDialability()).toEqual({ dialable: false, publicAddr: null });
  });

  it("returns the configured dialability", () => {
    const dial: Dialability = { dialable: true, publicAddr: "/ip4/203.0.113.5/tcp/4001/p2p/PEER" };
    const stub = new LocalAutoNatStub({ dialability: dial });
    expect(stub.getDialability()).toEqual(dial);
  });

  it("onChange fires with the new value when dialability changes", () => {
    const stub = new LocalAutoNatStub();
    const seen: Dialability[] = [];
    const unsub = stub.onChange((d) => seen.push(d));
    stub.setDialability({ dialable: true, publicAddr: "/ip4/198.51.100.7/tcp/4001/p2p/PEER" });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({ dialable: true, publicAddr: "/ip4/198.51.100.7/tcp/4001/p2p/PEER" });
    unsub();
    stub.setDialability({ dialable: false, publicAddr: null });
    expect(seen).toHaveLength(1); // unsubscribed — no further notifications
  });
});

// ─── SI-002: probers restricted to manifest directory nodes ──────────────────

describe("SI-002: AutoNAT probers are exclusively the directory nodes (no rogue responder)", () => {
  it("a non-manifest peer is never part of the prober set", () => {
    const directoryAddrs = ["/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWDir"];
    const stub = new LocalAutoNatStub({ probers: directoryAddrs });
    const rogue = "/ip4/192.0.2.66/tcp/4001/p2p/12D3KooWRogue";
    // The rogue's address is not in the configured (manifest-derived) prober set.
    expect(stub.getProbers()).not.toContain(rogue);
    expect(stub.getProbers()).toEqual(directoryAddrs);
  });

  it("reconnecting state (no connected directory nodes) yields an empty prober set", () => {
    const stub = new LocalAutoNatStub({ probers: ["/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWDir"] });
    stub.setProbers([]); // simulate all directory nodes unreachable
    expect(stub.getProbers()).toEqual([]);
    // AutoNAT cannot run — dialability stays the conservative default.
    expect(stub.getDialability()).toEqual({ dialable: false, publicAddr: null });
  });
});

// ─── AC-003: real AutoNAT dialability (CELLO_E2E_LIVE only) ───────────────────

const liveOnly = describe.skipIf(!process.env["CELLO_E2E_LIVE"]);

liveOnly("AC-003: real AutoNAT probe confirms dialability (live)", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("a publicly-reachable standing receiver reports dialable:true with a non-null publicAddr", async () => {
    // CELLO_E2E_LIVE: the host must be publicly reachable (e.g. a LAN/public IP
    // where AutoNAT dial-back from directory-node probers succeeds). We bind a
    // real (non-loopback) interface so libp2p can observe and confirm an external
    // address. In-process stubs cannot satisfy this AC.
    const node = await createNode({
      keyProvider: keyProvider(),
      // Bind all interfaces so a real external address can be observed/confirmed.
      listenAddresses: ["/ip4/0.0.0.0/tcp/0"],
      nodeType: "standing_receiver",
    });
    await node.start();
    scope.addCleanup(async () => { try { await node.stop(); } catch {} });

    // Wait for the AutoNAT probe cycle to confirm an external address.
    const dialable = await new Promise<Dialability>((resolve) => {
      const unsub = node.onDialabilityChange((d) => {
        if (d.dialable) { unsub(); resolve(d); }
      });
      // Fallback: resolve with the current value after the probe window.
      setTimeout(() => { unsub(); resolve(node.getDialability()); }, 30_000);
    });

    expect(dialable.dialable).toBe(true);
    expect(dialable.publicAddr).not.toBeNull();
    expect(typeof dialable.publicAddr).toBe("string");
  });
});
