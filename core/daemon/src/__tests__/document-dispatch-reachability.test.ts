/**
 * DOD-DOC-TOOLS-1 — the verbs are reachable OVER THE SOCKET.
 *
 * The first attempt at this line added seven handlers and could not be called. `renderedHandlers`
 * was a snapshot copy of the handler map taken at line 3112; `registerDocumentHandlers` wrote into
 * the original at line 3357, 245 lines and one `await ipcServer.start()` later. Every `cello_doc_*`
 * verb answered `method_not_found`, whose guidance blames version skew between the shim and the
 * daemon — so an operator would re-pin, reinstall, restart, and find both sides matching, because
 * the real cause was an ordering gap in one composition root.
 *
 * Nothing caught it. `document-handlers.test.ts` builds its own `Map` and calls `handlers.get(verb)`
 * on it, so it proves the FUNCTION works when you hold a reference — which is not the claim. The
 * capability-registration guard scans source text for `handlers.set("cello_doc_list"` and cannot
 * know which map that is. Both stay green with the wiring deleted outright.
 *
 * So this one goes through the socket. It is the only assertion in the suite that can tell
 * "registered" from "dispatchable", and that distinction is the entire content of this DoD line.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Buffer } from "node:buffer";
import { FileKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { createNode } from "@cello-protocol/transport";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import { DUAL_SURFACE_VERBS } from "../vocabulary.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { ConnectResult, SignalingStream, CelloNode } from "@cello-protocol/transport";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

class RealNodeFactory implements ISessionNodeFactory {
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    return createNode({
      keyProvider: generateKeypair(),
      listenAddresses: ["/ip4/127.0.0.1/tcp/0"],
      connectionGater: config.connectionGater,
      nodeType: config.nodeType,
    });
  }
}

function makeInjectableSignaling(): () => Promise<ConnectResult> {
  const stream: SignalingStream = { send: async () => {}, onMessage: () => {}, close: () => {} };
  return async () => ({ stream, directoryNodeId: "fake-dir", manifestVersion: 1 });
}

describe("the document verbs answer over the daemon socket", () => {
  let tempDir: string;
  let priorCelloEnv: string | undefined;
  const handles: Array<Awaited<ReturnType<typeof startDaemon>>> = [];

  beforeEach(async () => {
    priorCelloEnv = process.env["CELLO_ENV"];
    process.env["CELLO_ENV"] = "local";
    tempDir = await mkdtemp(join(tmpdir(), "cello-doc-dispatch-"));
    handles.length = 0;
  });

  afterEach(async () => {
    for (const h of handles) await h.stop();
    if (priorCelloEnv === undefined) delete process.env["CELLO_ENV"];
    else process.env["CELLO_ENV"] = priorCelloEnv;
    await rm(tempDir, { recursive: true, force: true });
  });

  async function boot() {
    const dir = join(tempDir, "a");
    await mkdir(dir, { recursive: true });
    const agentDir = join(dir, "agents", "alice");
    await mkdir(agentDir, { recursive: true });
    const kp = await FileKeyProvider.load(join(agentDir, "key"));
    const pubkey = Buffer.from(await kp.getPublicKey()).toString("hex");

    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: dir,
      socketPath: join(dir, "daemon.sock"),
      lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: makeLogger(),
      sessionNodeFactory: new RealNodeFactory(),
      signalingConnect: makeInjectableSignaling(),
    };
    const h = await startDaemon(config);
    handles.push(h);
    const client = await connectToDaemon(join(dir, "daemon.sock"));
    await client.send("ipc.connect", { clientType: "cli" });
    await client.send("cello_use_agent", { name: "alice" });
    return { client, pubkey, handle: h };
  }

  it("every cello_doc_* verb dispatches — none answers method_not_found", async () => {
    const { client } = await boot();
    // Driven from the VOCABULARY, not a hand-typed list: the table is the promise made to the
    // operator, so an eighth verb declared there and never wired fails here without anyone
    // remembering to extend this test.
    const docVerbs = DUAL_SURFACE_VERBS.map((v) => v.mcp).filter((m) => m.startsWith("cello_doc_"));
    expect(docVerbs.length).toBeGreaterThan(0);

    const unreachable: string[] = [];
    for (const verb of docVerbs) {
      // Deliberately called with NO parameters. A refusal about a missing argument proves dispatch;
      // `method_not_found` proves the opposite, and it is the only answer being tested for.
      const res = (await client.send(verb, {})) as { error?: { code?: string } };
      if (res?.error?.code === "method_not_found") unreachable.push(verb);
    }

    expect(
      unreachable,
      "These verbs are declared in the vocabulary, have handlers in the source, and cannot be " +
        "called. The operator-visible symptom is method_not_found, whose guidance blames shim/daemon " +
        "version skew — so nobody looks at the composition root, which is where the fault is.",
    ).toEqual([]);
  }, 30_000);

  it("dispatches a real answer, not merely a non-error", async () => {
    const { client } = await boot();
    // An empty list from a fresh daemon is the correct answer and it is a REAL one — it means the
    // handler ran, resolved the agent, and queried the store.
    expect(await client.send("cello_doc_list", {})).toMatchObject({ ok: true, documents: [] });
    expect(await client.send("cello_doc_inbox", {})).toMatchObject({ ok: true, proposals: [] });
    // And a refusal that names the argument, which is a handler talking rather than the router.
    expect(await client.send("cello_doc_read", {})).toMatchObject({ reason: "invalid_document_id" });
  }, 30_000);

  it("a handler registered AFTER the server started is still dispatchable", async () => {
    const { client, handle } = await boot();
    // THE PROPERTY ITSELF. The first version of this test called `cello_doc_list` and asserted
    // ok:true — a duplicate of the test above, claiming a property it never exercised. It would
    // have stayed green against the snapshot copy this whole file exists to prevent, as long as the
    // document handlers happened to be registered early enough.
    //
    // So: register something genuinely new, after `start()` has already resolved, and call it.
    handle.getHandlers().set("cello_test_late_binding", async () => ({ ok: true, late: true }));
    expect(await client.send("cello_test_late_binding", {})).toMatchObject({ ok: true, late: true });
  }, 30_000);
});
