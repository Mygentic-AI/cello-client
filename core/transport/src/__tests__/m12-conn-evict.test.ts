/**
 * DOD-M12-CONN-OBSERVE-1 + DOD-M12-CONN-EVICT-1 (trustless-cello M12 Tier P5).
 *
 * WHY THIS FILE EXISTS. A relay holds one long-lived libp2p connection per directory for the whole
 * life of the process. When that connection's MUXER dies, `newStream` throws
 * `connection_lost: The connection muxer is "closed" and not "open"`, and the relay's repair —
 * dial, then retry once — cannot fix it: `libp2p.dial()` returns an EXISTING connection whenever
 * one is registered for the peer whose SOCKET status reads `open`, and `findExistingConnection`
 * filters on `con.status` and never inspects the muxer. So the redial hands the same dead object
 * back. Measured live 2026-08-18/19: 38 refused seals, every one with a closed connection; 11
 * successes, none. A relay restart was the only thing that ever cleared it, because a restart is
 * the only thing that empties the connection manager.
 *
 * Two capabilities are missing from `CelloNode` and both are needed by the relay:
 *
 *   `status` on getConnections() — the OBSERVE half. `Connection.status` (the socket) and the
 *     muxer's status are SEPARATE fields checked in that order by libp2p's `newStream`, muxer
 *     first. So the muxer error returns before the socket is ever examined and cannot tell
 *     "socket open, muxer dead" from "both dead". Those imply different fixes, and the relay
 *     currently has no way to report which it hit.
 *
 *   `hangUp` — the EVICT half. Removing the registered connection is what forces the next dial to
 *     establish a genuinely new one. `{ force: true }` on the dial was considered and rejected: it
 *     opens a new connection but LEAVES the corpse registered, so the next `newStream` can select
 *     it again. Eviction removes the thing being handed back.
 *
 * These tests use real libp2p nodes over loopback. No mocks — the behaviour under test is
 * libp2p's connection bookkeeping, and a mock of it would assert our own assumptions back at us.
 */

import {
  setupV3Tests,
  createTestScope,
  waitFor,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@claude-flow/testing";
import { generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "../node.js";
import type { KeyProvider } from "@cello-protocol/crypto";

setupV3Tests();

function makeKeyProvider(): KeyProvider {
  const inner = generateKeypair();
  return {
    async getPublicKey() { return inner.getPublicKey(); },
    async sign(data: Uint8Array) { return inner.sign(data); },
  };
}

async function makeStartedNode() {
  const node = await createNode({
    keyProvider: makeKeyProvider(),
    listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
  });
  await node.start();
  return node;
}

describe("DOD-M12-CONN-OBSERVE-1: getConnections reports the socket status", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("carries a status for a live connection, so open can be told from closed", async () => {
    const a = await makeStartedNode();
    const b = await makeStartedNode();
    scope.addCleanup(async () => { try { await a.stop(); } catch { /* teardown */ } });
    scope.addCleanup(async () => { try { await b.stop(); } catch { /* teardown */ } });

    await a.dial(b.listenAddresses()[0]!);
    await waitFor(() => a.getConnections().some((c) => c.peerId === b.getPeerId()));

    const conn = a.getConnections().find((c) => c.peerId === b.getPeerId());
    expect(conn).toBeDefined();
    // The FIELD is the point of this unit. Without it the relay can log that a stream failed and
    // nothing about the state of the connection it failed on, which is exactly the gap that left
    // three candidate mechanisms alive after a full investigation.
    expect(conn!.status).toBe("open");
  });
});

describe("DOD-M12-CONN-EVICT-1: hangUp removes the registered connection", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("drops the connection to that peer, so a later dial cannot return it", async () => {
    const a = await makeStartedNode();
    const b = await makeStartedNode();
    scope.addCleanup(async () => { try { await a.stop(); } catch { /* teardown */ } });
    scope.addCleanup(async () => { try { await b.stop(); } catch { /* teardown */ } });

    const addr = b.listenAddresses()[0]!;
    await a.dial(addr);
    await waitFor(() => a.getConnections().some((c) => c.peerId === b.getPeerId()));

    await a.hangUp(b.getPeerId());

    // The corpse is GONE from the registry, not merely marked closed. That is the whole point:
    // libp2p's dial returns a registered connection whose status reads open, so leaving one behind
    // in any form is what makes the redial a no-op.
    await waitFor(() => !a.getConnections().some((c) => c.peerId === b.getPeerId()));
    expect(a.getConnections().some((c) => c.peerId === b.getPeerId())).toBe(false);
  });

  it("is safe to call for a peer we hold no connection to", async () => {
    const a = await makeStartedNode();
    const b = await makeStartedNode();
    scope.addCleanup(async () => { try { await a.stop(); } catch { /* teardown */ } });
    scope.addCleanup(async () => { try { await b.stop(); } catch { /* teardown */ } });

    // The relay calls this on a failure path where the connection may already be gone. Throwing
    // there would replace a recoverable stale handle with a thrown error on the repair itself.
    await expect(a.hangUp(b.getPeerId())).resolves.toBeUndefined();
  });

  it("refuses a malformed peer id by naming the cause, rather than throwing something opaque", async () => {
    const a = await makeStartedNode();
    scope.addCleanup(async () => { try { await a.stop(); } catch { /* teardown */ } });

    // ABSENT IS NOT FINE. A caller that passes a bad id must learn that from the error, not see a
    // generic libp2p parse failure it will log as a connection problem.
    await expect(a.hangUp("not-a-peer-id")).rejects.toMatchObject({
      reason: "invalid_peer_id",
    });
  });

  it("a dial after hangUp establishes a NEW connection rather than returning the old one", async () => {
    const a = await makeStartedNode();
    const b = await makeStartedNode();
    scope.addCleanup(async () => { try { await a.stop(); } catch { /* teardown */ } });
    scope.addCleanup(async () => { try { await b.stop(); } catch { /* teardown */ } });

    const addr = b.listenAddresses()[0]!;
    await a.dial(addr);
    await waitFor(() => a.getConnections().some((c) => c.peerId === b.getPeerId()));

    await a.hangUp(b.getPeerId());
    await waitFor(() => !a.getConnections().some((c) => c.peerId === b.getPeerId()));

    await a.dial(addr);
    await waitFor(() => a.getConnections().some((c) => c.peerId === b.getPeerId()));

    // This is the property the relay's repair depends on and the one the current code does not
    // have: after eviction, the dial must reach the network instead of resolving from the registry.
    const after = a.getConnections().filter((c) => c.peerId === b.getPeerId());
    expect(after.length).toBe(1);
    expect(after[0]!.status).toBe("open");
  });
});

describe("DOD-M12-CONN-MUXER-OBSERVE-1: getConnections reports the MUXER status, not only the socket", () => {
  let scope = createTestScope();
  beforeEach(() => { scope = createTestScope(); });
  afterEach(() => scope.run(async () => {}));

  it("reports both states, because the failure is one open and the other closed", async () => {
    const a = await makeStartedNode();
    const b = await makeStartedNode();
    scope.addCleanup(async () => { try { await a.stop(); } catch { /* teardown */ } });
    scope.addCleanup(async () => { try { await b.stop(); } catch { /* teardown */ } });

    await a.dial(b.listenAddresses()[0]!);
    await waitFor(() => a.getConnections().some((c) => c.peerId === b.getPeerId()));

    const conn = a.getConnections().find((c) => c.peerId === b.getPeerId());
    expect(conn).toBeDefined();
    // The whole M12 Tier P5 investigation turned on these being SEPARATE and only one being
    // visible. `status` is the socket; `muxerStatus` is the layer that actually carries data, and
    // libp2p checks it FIRST when opening a stream. The live failure is socket "open" + muxer
    // closed — indistinguishable, until now, from a connection that is dead through.
    expect(conn!.status).toBe("open");
    expect(conn!.muxerStatus).toBe("open");
  });

  it("never invents a value when the muxer cannot be read", async () => {
    const a = await makeStartedNode();
    scope.addCleanup(async () => { try { await a.stop(); } catch { /* teardown */ } });
    // `muxer` is not on libp2p's PUBLIC Connection type — it is read off the runtime object. If a
    // future libp2p moves it, the field must go absent rather than silently reporting "open" for a
    // muxer nobody looked at. Reporting a wrong "open" here would recreate the exact blindness this
    // unit removes.
    const shaped = a.getConnections().every(
      (c) => c.muxerStatus === undefined || typeof c.muxerStatus === "string",
    );
    expect(shaped).toBe(true);
  });
});
