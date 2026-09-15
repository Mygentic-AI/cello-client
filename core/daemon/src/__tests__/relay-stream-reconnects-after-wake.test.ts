/**
 * The relay stream must come back on its own after a laptop wakes.
 *
 * Live 2026-09-15, lid-close test: the Mac slept 09:55:15 → 09:59:43 while Hermes sent three
 * messages. At wake the relay stream's reader ended on a timeout and `#reconnectFromAnySession`
 * made ONE attempt, at 09:59:42 — before the network was back, so the dial failed. Nothing tried
 * again. Twelve minutes later the Mac still had no relay stream: no `leaf_deliver` for the three
 * messages, and a session that read `alive` and received nothing. Only a SEND re-dials, and a
 * receiving agent has nothing to send.
 *
 * Pinned against a real libp2p relay that is stopped and restarted at the same peer id and port,
 * so the first reconnect genuinely fails the way it did at wake.
 */
import { describe, it, expect, afterEach } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { createNode, type CelloNode } from "@cello-protocol/transport";
import { generateKeypair, verify } from "@cello-protocol/crypto";
import type { Stream } from "@libp2p/interface";
import { AgentRelayClient } from "../session-relay-client.js";
import type { Logger } from "../types.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });
const RELAY_PROTOCOL_ID = "/cello/relay/1.0.0";
const AUTH_DOMAIN = "CELLO-RELAY-AUTH-v1";

type Ev = { event: string; context: Record<string, unknown> };
function makeLogger(): { logger: Logger; events: Ev[] } {
  const events: Ev[] = [];
  const push = (event: string, context?: Record<string, unknown>) => { events.push({ event, context: context ?? {} }); };
  return { logger: { debug: push, info: push, warn: push, error: push }, events };
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitUntil(fn: () => boolean, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) { if (fn()) return true; await wait(50); }
  return fn();
}

/** A relay that authenticates and then holds the stream open, like the real one does. */
async function startRelay(seed: Uint8Array, port: number): Promise<CelloNode> {
  // The transport seed fixes the peer id, so a restart is the SAME relay coming back.
  const node = await createNode({
    keyProvider: generateKeypair(), transportPrivateKey: seed, listenAddresses: [`/ip4/127.0.0.1/tcp/${String(port)}`],
  });
  await node.start();
  await node.handle(RELAY_PROTOCOL_ID, (stream: Stream) => {
    void (async () => {
      try {
        const nonce = new Uint8Array(32).fill(9);
        stream.send(lp.encode.single(CBOR_ENC.encode({ type: "relay_auth_challenge", nonce }) as Uint8Array));
        for await (const chunk of lp.decode(stream)) {
          const bytes = chunk instanceof Uint8Array ? chunk : (chunk as unknown as { slice(): Uint8Array }).slice();
          const frame = decode(bytes) as Record<string, unknown>;
          if (frame["type"] !== "relay_auth_response") continue;
          const pubkey = frame["pubkey"] as Uint8Array;
          const msg = new Uint8Array(Buffer.concat([Buffer.from(AUTH_DOMAIN, "utf8"), nonce, pubkey]));
          if (!verify(pubkey, new Uint8Array(createHash("sha256").update(msg).digest()), frame["signature"] as Uint8Array)) break;
          stream.send(lp.encode.single(CBOR_ENC.encode({ type: "relay_auth_ok" }) as Uint8Array));
        }
      } catch { /* the relay was stopped under the stream — that is the scenario */ }
    })();
  });
  return node;
}

describe("the relay stream reconnects by itself when its first reconnect attempt fails", () => {
  const cleanup: Array<() => Promise<unknown>> = [];
  afterEach(async () => { for (const c of cleanup.splice(0).reverse()) await c().catch(() => undefined); });

  it("★★★ relay drops, the immediate reconnect fails, the relay returns — the client reconnects with no send", async () => {
    const relayKey = new Uint8Array(randomBytes(32));
    let relay = await startRelay(relayKey, 0);
    const relayAddr = relay.listenAddresses().find((a) => a.includes("/p2p/"))!;
    const port = Number(/\/tcp\/(\d+)\//.exec(relayAddr)![1]);

    const client = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    await client.start();
    cleanup.push(() => client.stop());

    const agentKp = generateKeypair();
    const { logger, events } = makeLogger();
    const rc = new AgentRelayClient({
      relayPeerId: relay.getPeerId(),
      relayAddrs: [relayAddr],
      keyProvider: agentKp,
      senderPubkey: await agentKp.getPublicKey(),
      logger,
      reconnectRetryMs: 200,
    });
    cleanup.push(async () => { rc.close(); });
    rc.registerSession("ab".repeat(16), client);

    expect(await rc.connect(client), "PRECONDITION: the first connect succeeds").toBe(true);
    const connected = () => events.filter((e) => e.event === "session.relay.connected").length;
    expect(connected()).toBe(1);

    // The laptop sleeps: the relay link dies and, as at wake, the network is not back yet.
    await relay.stop();
    expect(
      await waitUntil(() => events.some((e) => e.event === "session.relay.dial.failed"), 10_000),
      "PRECONDITION: the reconnect attempt made at the moment of loss must fail, as it did live",
    ).toBe(true);

    // The network returns: the same relay, same peer id, same port.
    relay = await startRelay(relayKey, port);
    cleanup.push(() => relay.stop());

    expect(
      await waitUntil(() => connected() >= 2, 10_000),
      "one failed attempt must not be the last one while a session still depends on this stream — " +
        "that is how three messages sat undelivered for twelve minutes after a wake",
    ).toBe(true);
  }, 40_000);

  it("stops retrying once no session depends on the stream", async () => {
    const relay = await startRelay(new Uint8Array(randomBytes(32)), 0);
    const relayAddr = relay.listenAddresses().find((a) => a.includes("/p2p/"))!;
    const client = await createNode({ keyProvider: generateKeypair(), listenAddresses: ["/ip4/127.0.0.1/tcp/0"] });
    await client.start();
    cleanup.push(() => client.stop());
    const agentKp = generateKeypair();
    const { logger, events } = makeLogger();
    const rc = new AgentRelayClient({
      relayPeerId: relay.getPeerId(), relayAddrs: [relayAddr], keyProvider: agentKp,
      senderPubkey: await agentKp.getPublicKey(), logger, reconnectRetryMs: 100,
    });
    cleanup.push(async () => { rc.close(); });
    const sid = "cd".repeat(16);
    rc.registerSession(sid, client);
    expect(await rc.connect(client)).toBe(true);

    await relay.stop();
    await waitUntil(() => events.some((e) => e.event === "session.relay.dial.failed"), 10_000);
    rc.unregisterSession(sid);
    await wait(300);
    const before = events.filter((e) => e.event === "session.relay.dial.failed").length;
    await wait(1_000);
    expect(
      events.filter((e) => e.event === "session.relay.dial.failed").length,
      "with no session left there is nothing to deliver to, so dialling a dead relay is pure churn",
    ).toBe(before);
  }, 40_000);
});
