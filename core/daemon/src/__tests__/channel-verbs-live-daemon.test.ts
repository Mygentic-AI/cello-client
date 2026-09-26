/**
 * M16 018-PUBCOLLECT — the four channel verbs against a REAL daemon, over a REAL socket.
 *
 * ⚠️ **THIS IS THE LAYER EVERY EXPENSIVE DEFECT IN THIS UNIT LIVED IN.** The unit tests build a
 * publisher from seams and prove its decisions; the enforcer runs publisher and collector across OS
 * processes. Both bypass the handlers, the wiring and the CLI — so all of these shipped green:
 *
 *   - the verbs were registered into a map nothing wired, reachable from no surface at all;
 *   - nothing could write a channel's relay list, so every verb answered `channel_unknown` for
 *     every channel, for ever;
 *   - `resend` demanded a relay multiaddr the CLI never sent, so it could not succeed;
 *   - the clock-skew retry looked its key up under the empty string and was always `null`.
 *
 * Each one is invisible from either side alone and obvious the moment a daemon is asked to do the
 * thing an operator would ask it to do. That is what this file does and all it does — it asserts
 * the verbs are REACHABLE and answer coherently, not that a relay took anything, because there is
 * no relay here. Delivery is the enforcer's job.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { FileKeyProvider, decryptBody, type GroupKey } from "@cello-protocol/crypto";
import { decodeBroadcastArtifact } from "@cello-protocol/protocol-types";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";

// 035-INFOCLI item 5: a channel relay is a /p2p-terminated multiaddr — the peer id authenticates it
// on connect. The old loose form (no /p2p) is now refused by `cello_channel_config`.
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X";

describe("M16 018-PUBCOLLECT: the channel verbs on a live daemon", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let client: IpcClient | null;
  /** alice's public key: she is the agent AND, for this test, the channel. */
  let channelHex: string;

  const silent: Logger = {
    debug: () => undefined, info: () => undefined, warn: () => undefined, error: () => undefined,
  } as unknown as Logger;

  async function config(): Promise<DaemonConfig> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    // The CHANNEL is its own identity, not alice's key: setup refuses an ordinary agent's key.
    await mkdir(join(tempDir, "agents", "bcast"), { recursive: true });
    const kp = await FileKeyProvider.load(join(tempDir, "agents", "bcast", "key"));
    channelHex = Buffer.from(await kp.getPublicKey()).toString("hex");
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: silent,
    };
  }

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-m16-verbs-"));
    handle = null;
    client = null;
    handle = await startDaemon(await config());
    // Mark `bcast` a registered channel identity, as `cello channel create` does.
    handle.getSessionNodeManager().getDb().prepare("UPDATE agents SET channel = 1 WHERE agent_name = 'bcast'").run();
    client = await connectToDaemon(join(tempDir, "daemon.sock"));
    await client.send("ipc.connect", { clientType: "cli" });
  });

  afterEach(async () => {
    if (client) { try { client.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  const call = (verb: string, params: Record<string, unknown>): Promise<Record<string, unknown>> =>
    client!.send(verb, params) as Promise<Record<string, unknown>>;

  it("27. all five verbs are REACHABLE on the operator's socket", () => {
    const verbs = [...handle!.getHandlers().keys()];
    /**
     * ⚠️ The check that would have caught 017's hole and this unit's first cut. A handler module
     * that is written, compiled and tested but never registered is a feature that does not exist,
     * and nothing else in this file can run if this fails.
     */
    for (const verb of [
      "cello_channel_config", "cello_channel_publish",
      "cello_channel_info_set", "cello_channel_prune", "cello_channel_resend",
      // M16 022: the SUBSCRIBER's three. Their absence is what made channels a feature you could
      // publish to and nobody could subscribe to, for five orders.
      "cello_channel_info", "cello_channel_join", "cello_channel_read",
    ]) {
      expect(verbs, `${verb} is not registered — the module is wired to nothing`).toContain(verb);
    }
  });

  it("33. M16 022 — join REACHES the session layer, and a failure to open one says what happened", async () => {
    /**
     * ⚠️ **THE TEST THAT WOULD HAVE CAUGHT THE FIRST CUT OF THIS VERB, and did not exist.** Every
     * unit test stubbed the daemon seam, so all thirteen were green while `join` could never
     * succeed: it passed `target` where the negotiator reads `target_pubkey` and read back
     * `session_id` where the handler returns `sessionId`. Both were invisible from either side
     * alone and obvious the moment a real daemon was asked to do the thing.
     *
     * There is no directory here, so the join cannot complete — that is fine and is the point. What
     * this asserts is that the verb runs through the REAL socket, reaches the REAL session path,
     * and comes back with a reason that names what actually stopped it. A field-name bug produced
     * `no_session` with a detail about "the admin", which pointed at the counterparty for a fault
     * in the caller.
     */
    /**
     * ⚠️ **SET UP FIRST, AND THAT IS WHAT GIVES THIS TEETH.** With no channel recorded, the admin
     * lookup fails before the session path is ever reached, and the test passes whatever the
     * session code does — which is exactly how the first version of this test failed to catch the
     * bug it was written for. A channel this daemon holds resolves its admin LOCALLY, so `join`
     * runs all the way to opening a session.
     */
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "open", relays: [RELAY_A, RELAY_B],
    });

    const answer = await call("cello_channel_join", {
      agent: "alice", channel: channelHex,
    }) as { ok: boolean; reason?: string; detail?: string };

    expect(answer.ok, "there is no counterparty to admit it in this harness").toBe(false);
    // It reached the SESSION path — not the lookup, and not a caller that never got that far.
    expect(answer.reason, `unexpected refusal ${String(answer.reason)}`).toBe("no_session");
    /**
     * ⚠️ And the detail is the SESSION LAYER'S OWN reason. The bug this catches passed `target`
     * where the negotiator reads `target_pubkey`, so it came back `invalid_target_pubkey` — a
     * fault in the caller, reported as though the counterparty were unreachable.
     */
    expect(answer.detail, "the session layer's real reason, not a summary").toBeDefined();
    expect(answer.detail).not.toBe("invalid_target_pubkey");
  });

  it("34. M16 022 — read on a channel this agent does not follow is refused by name", async () => {
    const answer = await call("cello_channel_read", {
      agent: "alice", channel: channelHex,
    }) as { ok: boolean; reason?: string };
    expect(answer.ok).toBe(false);
    expect(answer.reason, "the operator is told they follow nothing, not given an empty list").toBe("not_subscribed");
  });

  it("035 item 5 — setup refuses a relay that is not a /p2p-terminated multiaddr", async () => {
    // Live evidence: `setup` accepted a bare hostname `relay-usc1.cello.mygentic.ai`, which cannot be
    // dialed — every later publish then failed on a relay with no peer to reach.
    const bare = await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public",
      relays: ["relay-usc1.cello.mygentic.ai", RELAY_B],
    });
    expect(bare["ok"]).toBe(false);
    expect(bare["reason"]).toBe("bad_relay");
    // The refusal names the offending value AND the expected shape.
    expect(String(bare["guidance"])).toContain("relay-usc1.cello.mygentic.ai");
    expect(String(bare["guidance"])).toContain("/p2p/");

    // A multiaddr WITHOUT the /p2p peer id is also refused — it is not a usable relay.
    const noPeer = await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public",
      relays: ["/dns4/relay-a.example/tcp/443/tls/ws", RELAY_B],
    });
    expect(noPeer["ok"]).toBe(false);
    expect(noPeer["reason"]).toBe("bad_relay");
    expect(String(noPeer["guidance"])).toContain("/dns4/relay-a.example/tcp/443/tls/ws");

    // Two proper /p2p multiaddrs are accepted.
    const good = await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public", relays: [RELAY_A, RELAY_B],
    });
    expect(good["ok"], JSON.stringify(good)).toBe(true);
  });

  it("036-PUBLICSUB (reviewer M-1): setup cannot CHANGE a channel's access; relays stay changeable", async () => {
    // A channel's access is FIXED at create. The subscriber's read decides plaintext-vs-decrypt from
    // its stored access, so an admin flipping public→open would make existing readers try to decrypt
    // a public (plaintext) post — ciphertext as a post. Matches the directory's V67 note: a channel
    // that wants different access is a different channel.
    const created = await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public", relays: [RELAY_A, RELAY_B],
    });
    expect(created["ok"], JSON.stringify(created)).toBe(true);

    // Changing access on an existing channel is refused by name, and the stored access is untouched.
    const flip = await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "open", relays: [RELAY_A, RELAY_B],
    });
    expect(flip["ok"]).toBe(false);
    expect(flip["reason"]).toBe("access_is_fixed");
    const info = await call("cello_channel_info", { agent: "alice", channel: channelHex }) as { access?: string };
    expect(info.access, "access unchanged after a refused flip").toBe("public");

    // The SAME access with new relays is fine — relays remain changeable.
    const relayChange = await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public", relays: [RELAY_B, RELAY_A],
    });
    expect(relayChange["ok"], JSON.stringify(relayChange)).toBe(true);
  });

  it("035 item 1 — info on a channel this daemon ADMINISTERS carries access, guidance, relays", async () => {
    // The directory answers only the admin key; item 1 adds access/description/relays from the LOCAL
    // config the publisher wrote. Here alice administers her own channel, so info reports all three.
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public",
      relays: [RELAY_A, RELAY_B], guidance: "the original description",
    });
    const info = await call("cello_channel_info", { agent: "alice", channel: channelHex }) as
      { ok: boolean; adminPubkeyHex?: string; access?: string; guidance?: string; relays?: string[]; detail?: string };
    expect(info.ok, JSON.stringify(info)).toBe(true);
    expect(info.access).toBe("public");
    expect(info.guidance).toBe("the original description");
    expect(info.relays).toEqual([RELAY_A, RELAY_B]);
    // Administering the channel, it does NOT fall back to the "join to see the description" detail.
    expect(info.detail).toBeUndefined();
  });

  it("035 item 2 — info-set --guidance stores the new description before it deposits", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public",
      relays: [RELAY_A, RELAY_B], guidance: "the original description",
    });
    // Change the description. The deposit fails in this harness (no relay), but item 2's job is to
    // STORE the new text in the config first — which item 1's `info` reads back.
    await call("cello_channel_info_set", {
      agent: "alice", channel: channelHex, guidance: "the new description",
    });
    const info = await call("cello_channel_info", { agent: "alice", channel: channelHex }) as { guidance?: string };
    expect(info.guidance, "info-set with --guidance must have updated the stored description").toBe("the new description");
    // info-set WITHOUT guidance must NOT wipe the description — it only re-deposits.
    await call("cello_channel_info_set", { agent: "alice", channel: channelHex });
    const info2 = await call("cello_channel_info", { agent: "alice", channel: channelHex }) as { guidance?: string };
    expect(info2.guidance, "info-set with no guidance must leave the description alone").toBe("the new description");
  });

  it("038 Part A — a re-run of setup with new relays and NO guidance keeps the stored description", async () => {
    // Live evidence (F34): test-public's `channel info` showed guidance "" after later setup runs;
    // create had set it. `cello_channel_config` defaulted an absent guidance to "" and overwrote the
    // stored description on every re-setup — so changing relays wiped the channel's description.
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public",
      relays: [RELAY_A, RELAY_B], guidance: "the original description",
    });
    // Re-setup: change the relays, pass NO guidance. The stored description must survive.
    const resetup = await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public", relays: [RELAY_B, RELAY_A],
    });
    expect(resetup["ok"], JSON.stringify(resetup)).toBe(true);
    const info = await call("cello_channel_info", { agent: "alice", channel: channelHex }) as
      { guidance?: string; relays?: string[] };
    expect(info.guidance, "re-setup without guidance must keep the stored description").toBe("the original description");
    // ...and the relays DID change (a normal setup still changes relays — MUST NOT CHANGE item 1).
    expect(info.relays).toEqual([RELAY_B, RELAY_A]);
  });

  it("28. a channel must be SET UP before it can publish, and the refusal says so", async () => {
    const answer = await call("cello_channel_publish", {
      agent: "alice", channel: channelHex, title: "before setup", body: "body",
    });
    // Not a crash and not a silent success: the channel genuinely is unknown to this daemon.
    expect(answer["ok"]).toBe(false);
    expect(answer["reason"]).toBe("channel_unknown");
  });

  it("29. setup records the relays, and refuses a channel whose key this daemon does not hold", async () => {
    const good = await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public", relays: [RELAY_A, RELAY_B],
    });
    expect(good["ok"], JSON.stringify(good)).toBe(true);
    expect(good["relays"]).toEqual([RELAY_A, RELAY_B]);

    // ⚠️ A channel is an agent whose key this daemon holds. Recording relays for somebody else's
    // channel would leave every later verb failing on a key lookup, which describes neither the
    // mistake nor how to fix it.
    const foreign = await call("cello_channel_config", {
      agent: "alice", channel: "de".repeat(32), access: "public", relays: [RELAY_A, RELAY_B],
    });
    expect(foreign["ok"]).toBe(false);
    expect(foreign["reason"]).toBe("channel_key_not_held");
    expect(String(foreign["guidance"])).toContain("does not hold");
  });

  it("30. after setup, publish REACHES the relays and reports each one's real outcome", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public", relays: [RELAY_A, RELAY_B],
    });

    const answer = await call("cello_channel_publish", {
      agent: "alice", channel: channelHex, title: "the first post", body: "hello",
    });

    /**
     * ⚠️ **`no_relay_accepted` IS THE PASS HERE**, and the distinction is the whole value of this
     * test. Those two multiaddrs point at nothing, so a publisher that got as far as trying to
     * reach them is a publisher that screened, signed, logged and dialled. The failures this file
     * exists for produce `channel_unknown` (no config), `key_unavailable` (the empty-string
     * lookup), or no handler at all — never a relay that was contacted and did not answer.
     */
    expect(answer["ok"]).toBe(false);
    expect(answer["reason"]).toBe("no_relay_accepted");
    // And the post SURVIVES, so the guidance must not tell the operator to publish it again.
    expect(String(answer["guidance"])).toContain("resend");
  });

  it("31. resend runs with NO relay named — it refills every relay the channel publishes to", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public", relays: [RELAY_A, RELAY_B],
    });

    const answer = await call("cello_channel_resend", { agent: "alice", channel: channelHex });
    /**
     * ⚠️ Requiring a multiaddr here made the ONLY repair command an operator has impossible to run
     * from the terminal: the CLI sent no relay and the daemon answered `bad_relay`, always. It now
     * defaults to every configured relay.
     */
    expect(answer["ok"], JSON.stringify(answer)).toBe(true);
    expect(answer["relays"]).toEqual([
      { relay: RELAY_A, deposited: 0 },
      { relay: RELAY_B, deposited: 0 },
    ]);
  });

  it("32. prune tells the operator its relays are STILL HOLDING the posts when it could not reach them", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public", relays: [RELAY_A, RELAY_B],
    });
    // Publish one so the log has something to prune. It reaches no relay, which is fine.
    await call("cello_channel_publish", {
      agent: "alice", channel: channelHex, title: "to be pruned", body: "body",
    });

    const answer = await call("cello_channel_prune", {
      agent: "alice", channel: channelHex, through_seq: 1,
    });
    expect(answer["ok"]).toBe(true);
    expect(answer["pruned"]).toBe(1);
    /**
     * ⚠️ **NEITHER RELAY IS `ok`, AND THE OPERATOR IS TOLD.** The first version reported every relay
     * as successfully pruned without contacting any of them, so an operator deleting 500 posts was
     * shown two green relays while both kept serving every one.
     */
    const relays = answer["relays"] as Array<{ relay: string; ok: boolean }>;
    expect(relays.every((r) => !r.ok)).toBe(true);
    expect(String(answer["guidance"])).toContain("did not drop");
  });

  /**
   * The `channel_subscription_keys` rows this daemon holds for a channel, and the `channel_log`
   * bodies it stored — read straight from the live SQLCipher database, so the assertions are about
   * what was actually persisted, not what a seam reported.
   */
  const keyRowsFor = (channelHex: string): Array<{ generation: number; key: Uint8Array }> =>
    (handle!.getSessionNodeManager().getDb()
      .prepare(`SELECT generation, key FROM channel_subscription_keys WHERE channel_pubkey = ? ORDER BY generation ASC`)
      .all(channelHex.toLowerCase()) as Array<{ generation: number | bigint; key: Uint8Array }>)
      .map((r) => ({ generation: Number(r.generation), key: new Uint8Array(r.key) }));

  const logBodyAt = (channelHex: string, seq: number): Uint8Array => {
    const row = handle!.getSessionNodeManager().getDb()
      .prepare(`SELECT post_cbor FROM channel_log WHERE channel_pubkey = ? AND seq = ?`)
      .get(channelHex.toLowerCase(), seq) as { post_cbor: Uint8Array } | undefined;
    if (!row) throw new Error(`no channel_log row at seq ${String(seq)}`);
    // The SAME decoder channel-log-store.ts uses on every read — the stored bytes are authoritative.
    const decoded = decodeBroadcastArtifact(new Uint8Array(row.post_cbor));
    if (!decoded.ok) throw new Error(`post_cbor at seq ${String(seq)} does not decode: ${decoded.reason}`);
    return decoded.artifact.body;
  };

  const logCount = (channelHex: string): number =>
    Number((handle!.getSessionNodeManager().getDb()
      .prepare(`SELECT COUNT(*) AS n FROM channel_log WHERE channel_pubkey = ?`)
      .get(channelHex.toLowerCase()) as { n: number | bigint }).n);

  it("1. a private channel's post is stored as ciphertext that its own group key opens", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "invite_only", relays: [RELAY_A, RELAY_B],
    });

    /**
     * ⚠️ **028-GROUPPUB: THE PUBLISHER NOW MINTS GENERATION 1 IF NOBODY HAS JOINED YET.** Before it,
     * every publish on a non-public channel rejected `channel_group_key_unavailable` — the encrypt
     * step was a placeholder. There is no relay in this harness, so the deposit still fails
     * `no_relay_accepted`; what this asserts is that the body reached the LOG as ciphertext under the
     * channel's own group key, which is what makes the first member able to read a pre-join post.
     */
    const answer = await call("cello_channel_publish", {
      agent: "alice", channel: channelHex, title: "members only", body: "secret",
    }) as { ok: boolean; reason?: string; detail?: string };

    // The refusal that used to fire is gone — the post got past the encrypt step.
    expect(String(answer.reason ?? "")).not.toContain("channel_group_key_unavailable");
    expect(String(answer.detail ?? "")).not.toContain("channel_group_key_unavailable");

    // Exactly one group key, minted at generation 1 under the admin's own agent id.
    const keys = keyRowsFor(channelHex);
    expect(keys).toHaveLength(1);
    expect(keys[0].generation).toBe(1);

    // The stored body is NOT the plaintext bytes the publisher was handed for `body`.
    const body = logBodyAt(channelHex, 1);
    const publisherPlaintext = new TextEncoder().encode("secret"); // ChannelPublisher encodes `body`
    expect(Buffer.from(body).equals(Buffer.from(publisherPlaintext)), "stored body must be ciphertext").toBe(false);

    // And that same key opens it, back to exactly what the publisher encrypted.
    const gk: GroupKey = keys[0];
    const opened = decryptBody([gk], new Uint8Array(Buffer.from(channelHex, "hex")), 1, body);
    expect(opened.ok, opened.ok ? "" : opened.reason).toBe(true);
    if (opened.ok) expect(Buffer.from(opened.plaintext).equals(Buffer.from(publisherPlaintext))).toBe(true);
  });

  it("2. a second post reuses the generation-1 key — no key is minted per post", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "invite_only", relays: [RELAY_A, RELAY_B],
    });
    await call("cello_channel_publish", { agent: "alice", channel: channelHex, title: "one", body: "first" });
    await call("cello_channel_publish", { agent: "alice", channel: channelHex, title: "two", body: "second" });

    // Still exactly one key row: a per-post mint would leave two.
    const keys = keyRowsFor(channelHex);
    expect(keys).toHaveLength(1);
    expect(keys[0].generation).toBe(1);

    // The second body decrypts with it at seq 2 — the position is bound in, so the seq must match.
    const body2 = logBodyAt(channelHex, 2);
    const opened = decryptBody([keys[0]], new Uint8Array(Buffer.from(channelHex, "hex")), 2, body2);
    expect(opened.ok, opened.ok ? "" : opened.reason).toBe(true);
    if (opened.ok) expect(Buffer.from(opened.plaintext).toString("utf8")).toBe("second");
  });

  it("3. a PUBLIC channel mints nothing and stores plaintext", async () => {
    await call("cello_channel_config", {
      agent: "alice", channel: channelHex, access: "public", relays: [RELAY_A, RELAY_B],
    });
    await call("cello_channel_publish", { agent: "alice", channel: channelHex, title: "open", body: "anyone can read" });

    // No group key exists for a public channel — the encryptor returns undefined and never mints.
    expect(keyRowsFor(channelHex)).toHaveLength(0);
    // And the body is stored in the clear: encrypting it would lock out the readers it exists for.
    const body = logBodyAt(channelHex, 1);
    expect(Buffer.from(body).equals(Buffer.from("anyone can read", "utf8"))).toBe(true);
  });

  it("4. publish on a channel whose key this daemon does not hold is refused, and nothing is logged", async () => {
    const foreign = "de".repeat(32);
    const answer = await call("cello_channel_publish", {
      agent: "alice", channel: foreign, title: "not mine", body: "secret",
    }) as { ok: boolean; reason?: string };

    /**
     * ⚠️ The not-local path fires FIRST — there is no config for a channel this daemon does not hold,
     * so the publisher answers `channel_unknown` before the encrypt step. (`channel_group_key_unavailable`
     * from the no-admin branch of the encryptor is only reachable in a unit; the order says assert the
     * one that actually fires here.) Either way there must be NO plaintext fallback and NO post logged.
     */
    expect(answer.ok).toBe(false);
    expect(["channel_unknown", "channel_group_key_unavailable"]).toContain(answer.reason);
    expect(logCount(foreign)).toBe(0);
  });
});
