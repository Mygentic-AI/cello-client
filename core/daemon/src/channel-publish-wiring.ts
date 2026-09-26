/**
 * M16 018-PUBCOLLECT — everything the channel publishing verbs need, assembled in one place.
 *
 * ⚠️ The publisher is built PER CHANNEL AGENT and only when its key is loaded — a channel is an
 * agent whose key this daemon holds, and a publisher without one could sign nothing. `null` makes
 * the verb answer `channel_unknown`, which is the truth: this daemon does not publish for it.
 *
 * Order 017's own wiring gap is why this module is registered in the same commit as the handlers it
 * serves: a handler nothing calls is a feature that does not exist, and `startup-ordering.test.ts`
 * is what caught exactly that here.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { ScreenContext, ScreenVerdict } from "@cello-protocol/gateway";
import { Buffer } from "node:buffer";
import { decodeChannelInfo, verifyChannelInfo, type ChannelPosterRevocation } from "@cello-protocol/protocol-types";
import { registerChannelPublishHandlers, recordChannelConfig, depositChannelInfo } from "./channel-publish-handlers.js";
import { registerChannelCreateHandler } from "./channel-create-handler.js";
import { extractErrorMessage } from "./error-message.js";
import { DbIdentityStore } from "./db-identity-store.js";
import { ChannelPublisher } from "./channel-publisher.js";
import { ChannelLogStore } from "./channel-log-store.js";
import { ChannelConfigStore, type ChannelConfig } from "./channel-config-store.js";
import { ChannelRelayClient } from "./channel-relay-client.js";
import { ChannelCollector } from "./channel-collector.js";
import { createChannelFetchAuth } from "./channel-fetch-auth.js";
import { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import { ChannelPosterPassStore } from "./channel-poster-pass-store.js";
import { ChannelPosterPublisher } from "./channel-poster-publisher.js";
import { ChannelLanePositionStore } from "./channel-lane-position-store.js";
import { ChannelPosterGrantStore } from "./channel-poster-grant-store.js";
import { postingInfoExt } from "./channel-posting-admin.js";
import { ChannelInboxStore } from "./channel-inbox-store.js";
import { createChannelCollectTicker } from "./channel-collect-tick.js";
import { createChannelWakeSender, createPosterWakeSender, ringChannelMembers } from "./channel-wake-sender.js";
import type { ChannelNotify } from "./channel-membership-wiring.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

export interface ChannelPublishWiringDeps {
  handlers: Map<string, Handler>;
  logger: Logger;
  getDb: () => DaemonDatabase;
  /** M16 021-WAKE: who a post's doorbell is rung for. From the membership half, which owns the list. */
  activeMembers: (channelHex: string) => string[];
  /** M16 021-WAKE: the publishing agent's own directory connection, by agent NAME. */
  signalingFor: (agentName: string) => { sendRaw(frame: unknown): Promise<{ ok: boolean; reason?: string }> } | null;
  getNode: () => CelloNode | null;
  screenOutbound: (content: Uint8Array, ctx: ScreenContext) => Promise<ScreenVerdict>;
  /** Every agent this daemon loaded, read per lookup so one added after boot is publishable. */
  loadedAgents: ReadonlyArray<{ name: string; pubkey: string; keyProvider: KeyProvider }>;
  keyProviders: Map<string, KeyProvider>;
  /** Whether a loaded agent is a registered CHANNEL identity (not an ordinary agent). */
  isChannelAgent: (agentName: string) => boolean;
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
  /** 043-POSTERS: agent name → the stable agent_id the pass and subscription rows are keyed on. */
  resolveAgentId: (agentName: string) => string;
  /** 043-POSTERS: this agent's local moniker for a pubkey, or null. */
  contactMoniker?: (agentName: string, pubkeyHex: string) => string | null;
  /**
   * M16 019: the channel's current fetch key, signed, or undefined when this daemon holds no group
   * key for it. Injected rather than derived here so the membership half owns the group key and
   * this half never has to hold one.
   */
  currentFetchKey?: (channelHex: string) => Promise<{ pubkey: Uint8Array; time_ms: number; signature: Uint8Array } | undefined>;
  /**
   * M16 028-GROUPPUB: encrypt a post body under the channel's current group key. From the membership
   * half, which owns the group key, so this half never has to hold one. Rejects
   * `channel_group_key_unavailable` rather than ever falling back to plaintext.
   */
  encryptBody: (plaintext: Uint8Array, channelHex: string, seq: number) => Promise<Uint8Array>;
  /**
   * Online AND not explicitly switched off — the same pair every other background loop here reads.
   * Collecting for an agent the operator switched off is the kill switch failing to switch off.
   */
  isAgentOnline: (agentId: string) => boolean;
  /** M16 032-NOTICES: the content-free `channel_posts` doorbell, rung when a collect advances. */
  notify: ChannelNotify;
}

export function wireChannelPublishing(
  deps: ChannelPublishWiringDeps,
): {
  stop: () => void;
  collectNow: (agentId: string) => Promise<void>;
  /**
   * M16 034-LIFECYCLE: prune EVERYTHING a channel holds — through the log's last seq — on both
   * relays. The delete verb's second step. Lives here because the log and the publisher do, so the
   * membership half reaches it rather than reimplementing prune. `null` publisher (no key held) or
   * an empty log reports `pruned: 0` with no relay outcomes, never a false success.
   */
  pruneAllPosts: (agentName: string, channelHex: string) =>
    Promise<{ pruned: number; relays: Array<{ relay: string; ok: boolean; reason?: string }> }>;
  /**
   * 041-HELPTRUTH Part B: the last published seq for a channel, read from the log this half owns, or
   * null when the log holds nothing. The membership half uses it for the post count on an admin row.
   */
  channelLastSeq: (channelHex: string) => number | null;
  /** 043-POSTERS: sign and deposit a channel's info record (carrying its posting setting). */
  depositInfo: (agentName: string, channelHex: string) => Promise<unknown>;
  /**
   * 041-HELPTRUTH Part C: the channel's signed info record as its relays hold it, tried in order and
   * the first that answers. Uses the relay client this half owns; the membership half verifies the
   * record against the channel key before showing it to a member.
   */
  fetchInfo: (relays: string[], channelHex: string) => Promise<Uint8Array | null>;
  /** 045-NOTICEBELL: deposit a sealed notice on every relay; resolves with how many accepted it. */
  depositNotice: (relays: string[], record: Uint8Array) => Promise<number>;
  /** 045-NOTICEBELL: every record the relays hold at a slot, one per answering relay. */
  fetchNotices: (relays: string[], slot: Uint8Array) => Promise<Uint8Array[]>;
  /** 045-NOTICEBELL: ring named members about a notice, on the admin agent's own directory stream. */
  ringMembers: (adminAgentName: string, channelHex: string, members: string[]) => Promise<boolean>;
  /** The kill-switch check this half collects under — shared so the notice backstop honours it too. */
  isAgentOnline: (agentId: string) => boolean;
} {
  const { logger, keyProviders } = deps;

  const log = new ChannelLogStore(deps.getDb(), logger);
  const config = new ChannelConfigStore(deps.getDb(), logger);
  const relay = new ChannelRelayClient({ getNode: deps.getNode, logger });

  /**
   * The channel key is looked up BY PUBKEY, because that is what a post is signed with and what a
   * subscriber verifies against — the agent NAME is a display label and may be reused.
   */
  const channelKeyByPubkey = (channelHex: string): KeyProvider | null => {
    const want = channelHex.toLowerCase();
    const match = deps.loadedAgents.find((a) => a.pubkey.toLowerCase() === want);
    return match ? match.keyProvider : null;
  };

  const grants = new ChannelPosterGrantStore(deps.getDb(), logger);
  const posterPasses = new ChannelPosterPassStore(deps.getDb(), logger);
  // 043-POSTERS: publishing under a pass, for a channel this daemon does not hold the key to.
  const posterPublisher = new ChannelPosterPublisher({
    logger, log,
    passes: posterPasses,
    subscriptions: new ChannelSubscriptionStore(deps.getDb(), logger),
    deposit: (addr, req) => relay.deposit(addr, { post_cbor: req.post_cbor }),
    resolveAgentId: deps.resolveAgentId,
    getAgentKey: (name) => keyProviders.get(name) ?? null,
    screenOutbound: (bytes, ctx) =>
      deps.screenOutbound(bytes, {
        direction: "outbound",
        agentName: ctx.agentName,
        sessionId: `channel:${ctx.agentName}`,
        ...(ctx.correlationId !== undefined ? { correlationId: ctx.correlationId } : {}),
      }),
  });

  const buildPublisher = (agentName: string): ChannelPublisher | null => {
    if (!keyProviders.has(agentName)) return null;
    return new ChannelPublisher({
      poster: posterPublisher,
      logger,
      log,
      deposit: (addr, req) => relay.deposit(addr, {
        post_cbor: req.post_cbor,
        ...(req.fetch_key ? { fetch_key: req.fetch_key } : {}),
      }),
      /**
       * ⚠️ **THE KEY THAT MAKES AN EJECTION BITE AT THE RELAY.** Derived from the channel's current
       * group key, signed with the CHANNEL key because the post's signature does not cover it, and
       * sent with each deposit so a re-key reaches the relays on the very next post. `undefined`
       * means this daemon holds no group key for that channel — a public one, or one it does not
       * administer — and the relay then serves it to anyone, which for a public channel is correct.
       */
      currentFetchKey: deps.currentFetchKey,
      depositInfo: (addr, req) => relay.depositInfo(addr, { info_cbor: req.info_cbor }),
      prune: (addr, req) => relay.prune(addr, {
        channel_pubkey: Buffer.from(req.channelHex, "hex"),
        through_seq: req.throughSeq,
        time_ms: req.timeMs,
        signature: req.signature,
      }),
      relayHead: (addr, channelHex) => relay.head(addr, Buffer.from(channelHex, "hex")),
      // The screen has no session to name, so it names what it IS screening. Borrowing a session id
      // would file channel posts in another conversation's governance history.
      screenOutbound: (bytes, ctx) =>
        deps.screenOutbound(bytes, {
          direction: "outbound",
          agentName: ctx.agentName,
          sessionId: `channel:${agentName}`,
          ...(ctx.correlationId !== undefined ? { correlationId: ctx.correlationId } : {}),
        }),
      getChannelKey: channelKeyByPubkey,
      getAgentKey: (name) => keyProviders.get(name) ?? null,
      /**
       * ⚠️ **028-GROUPPUB: THE CHANNEL'S CURRENT GROUP KEY, MINTED AT GENERATION 1 IF NOBODY HAS
       * JOINED YET.** From the membership half, which owns the key — so a post published before the
       * first member is readable by that member, both paths reaching the same stored key. It rejects
       * `channel_group_key_unavailable` when this daemon holds no admin key for the channel; it never
       * falls back to plaintext, because depositing readable bytes under a members-only `access` is
       * the one failure the encrypt step exists to prevent.
       */
      encryptBody: deps.encryptBody,
      channelInfo: (channelHex) => config.get(channelHex),
      // 043-POSTERS: the posting setting and revocations the info record carries.
      postingExt: (channelHex) => postingInfoExt(config, grants, channelHex),
    });
  };

  /**
   * M16 021-WAKE. The publishing agent asks on ITS OWN directory stream — the directory checks the
   * caller is the channel's admin, so it has to be that agent's connection and not any that happens
   * to be open.
   */
  const sendWake = createChannelWakeSender({
    logger,
    activeMembers: (channelHex) => deps.activeMembers(channelHex),
    signalingFor: (agentId) => deps.signalingFor(agentId),
  });

  /**
   * 044-POSTERBELL: a POSTER rings the members itself the moment a relay accepts its post — the
   * admin is no longer in the path. Authorised by the poster's pass and one relay receipt, targeting
   * the members the admin last sent with the pass, minus the poster.
   */
  const ringPosterWake = createPosterWakeSender({
    logger,
    posterPassFor: (agentId, channelHex) => {
      const held = posterPasses.get(agentId, channelHex);
      return held ? { pass_cbor: held.pass_cbor, members: held.members } : null;
    },
    ownPubkeyHex: (agentName) => deps.loadedAgents.find((a) => a.name === agentName)?.pubkey ?? null,
    signalingFor: (agentName) => deps.signalingFor(agentName),
    resolveAgentId: deps.resolveAgentId,
  });

  const setChannelConfig = (agentName: string, channelHex: string, cfg: ChannelConfig):
    { ok: true } | { ok: false; reason: string; guidance?: string } => {
    // The channel key must be one this daemon HOLDS. Recording relays for a channel we cannot
    // sign for would leave every later verb failing on a key lookup, which describes neither the
    // mistake nor how to correct it.
    if (channelKeyByPubkey(channelHex) === null) {
      return {
        ok: false, reason: "channel_key_not_held",
        guidance: "This daemon does not hold that channel's key. Create a channel with 'cello channel create <name> <access>'.",
      };
    }
    // An ordinary agent's key is held too, and accepting it stored channel settings under an agent
    // that is no channel — which then showed in the channel list forever. Only a registered channel.
    const holder = deps.loadedAgents.find((a) => a.pubkey.toLowerCase() === channelHex.toLowerCase());
    if (!holder || !deps.isChannelAgent(holder.name)) {
      return {
        ok: false, reason: "not_a_channel",
        guidance: "That key belongs to an agent, not a channel. Create a channel with 'cello channel create <name> <access>'.",
      };
    }
    if (!keyProviders.has(agentName)) {
      return { ok: false, reason: "no_such_agent", guidance: `${agentName} is not an agent this daemon holds.` };
    }
    /**
     * ⚠️ **THE ADMIN AGENT IS RECORDED HERE, and it is what makes the channel joinable at all.**
     * `agentName` is the agent running the setup, and in this release the publisher and the admin
     * are the same operator — so that agent's key is the one a subscriber will check the answering
     * party against. Leaving it empty was how 019's first cut produced a channel that refused
     * every join with `not_admin_of_channel` on a channel it demonstrably administered.
     */
    const adminAgent = deps.loadedAgents.find((a) => a.name === agentName);
    config.set(channelHex, { ...cfg, admin_pubkey: adminAgent?.pubkey ?? "" }, Date.now());
    return { ok: true };
  };

  registerChannelPublishHandlers({
    handlers: deps.handlers,
    logger,
    resolveCurrentAgent: deps.resolveCurrentAgent,
    getPublisher: buildPublisher,
    wakeMembers: (agentName, channelHex) => sendWake(agentName, channelHex),
    // 044-POSTERBELL: a poster's own ring, carrying its pass and a relay receipt from the publish.
    ringPosterWake: (agentName, channelHex, receiptCbor) => ringPosterWake(agentName, channelHex, receiptCbor),
    setChannelConfig,
    // 035-INFOCLI item 2: read the current config so info-set can change only the guidance.
    getChannelConfig: (channelHex) => config.get(channelHex),
  });

  /**
   * M16 024-CREATE: the one command that brings a channel into existence, composing register →
   * config → info-set in-process. The three steps are the EXISTING code, reused: registration goes
   * through the `cello_register` handler, and config/info-set through the functions the publish
   * handlers were refactored onto (`recordChannelConfig` / `depositChannelInfo`).
   */
  registerChannelCreateHandler({
    handlers: deps.handlers,
    logger,
    resolveCurrentAgent: deps.resolveCurrentAgent,
    agentPubkey: (agentName) => deps.loadedAgents.find((a) => a.name === agentName)?.pubkey ?? null,
    registerChannel: async ({ name, adminName, adminPubkeyHex, access, correlationId }) => {
      const register = deps.handlers.get("cello_register");
      if (!register) {
        // Unreachable in production — registered at boot. A miss here is a WIRING bug, not an
        // operator error, so it throws rather than mislabelling itself as a failed create step.
        throw new Error("channel_create_wiring: the register handler is not wired");
      }

      // Refuse a name that is ALREADY a registered identity before anything runs. Re-registering it
      // would either clobber it or run a DKG for an identity that already exists.
      const existing = new DbIdentityStore(deps.getDb(), logger).getAgentForRevocation(name);
      if (existing && existing.state === "registered") {
        return {
          ok: false, reason: "channel_name_registered",
          guidance: `'${name}' is already a registered identity, so it cannot be created as a channel. Choose a different name.`,
        };
      }

      const rollbackMint = async (mintedHere: boolean): Promise<void> => {
        if (!mintedHere) return;
        const removeAgent = deps.handlers.get("cello_remove_agent");
        if (removeAgent) {
          // 024-CREATE item 6: a failed rollback used to be swallowed (.catch(() => undefined)),
          // leaving a half-made channel identity behind with NO trace of why cleanup did not run. Log
          // it with the name and error so the operator can remove it by hand; the create still fails.
          await removeAgent({ name }, "internal:channel-create").catch((err) => {
            logger.warn("channel.create.rollback_failed", { name, error: extractErrorMessage(err) });
          });
        }
      };

      // Fold the mint in: over MCP there is no cello_create_agent tool, so an agent could never
      // satisfy a "create the identity first" precondition. When the name has no local key, mint it
      // here through the existing handler; if the mint fails, nothing was created.
      let mintedHere = false;
      if (!keyProviders.has(name)) {
        const createAgent = deps.handlers.get("cello_create_agent");
        if (!createAgent) throw new Error("channel_create_wiring: the create-agent handler is not wired");
        const made = (await createAgent({ name }, "internal:channel-create")) as { ok?: boolean; reason?: string; guidance?: string };
        if (made?.ok !== true) {
          return { ok: false, reason: made?.reason ?? "agent_create_failed", guidance: made?.guidance };
        }
        mintedHere = true;
      }

      // The channel's own pubkey is its loaded K_local key — what a post is signed with and what
      // config/info-set are addressed by (the agent NAME is a mutable display label). Resolve it now,
      // BEFORE registration, because the admin signs over these very bytes.
      const kp = keyProviders.get(name);
      const channelPubkeyHex = deps.loadedAgents.find((a) => a.name === name)?.pubkey
        ?? (kp ? Buffer.from(await kp.getPublicKey()).toString("hex") : undefined);
      if (channelPubkeyHex === undefined) {
        await rollbackMint(mintedHere);
        throw new Error("channel_create_wiring: channel key not loaded after mint");
      }

      // ⚠️ THE WHOLE BASIS OF THE RIGHT: the admin — an already-registered agent — signs the channel's
      // K_local pubkey with its own K_local (Ed25519, RFC 8032). No token. The directory verifies this
      // against `admin_pubkey` and that the admin is a registered non-channel agent, then skips the
      // token gate. Signed here, where the admin's key provider is held.
      const adminKp = keyProviders.get(adminName);
      if (!adminKp) {
        await rollbackMint(mintedHere);
        return { ok: false, reason: "no_current_agent", guidance: `Agent '${adminName}' has no key on this daemon, so it cannot sign as the channel's admin.` };
      }
      // 024-CREATE item 3 — DOMAIN SEPARATION. Sign "cello.channel.admin.v1" || channelPubkey, never
      // the bare pubkey. The admin's K_local key also signs FROST auth and more; the tag binds this
      // signature to "authorize this channel" so one made for another purpose cannot be replayed here.
      // The directory verifies these exact bytes (channelAdminSigMessage) — the two change together.
      const adminSigMessage = Buffer.concat([
        Buffer.from("cello.channel.admin.v1", "utf8"),
        Buffer.from(channelPubkeyHex, "hex"),
      ]);
      const adminSignature = Buffer.from(await adminKp.sign(new Uint8Array(adminSigMessage))).toString("hex");

      const reg = (await register(
        { agent: name, channel: true, adminPubkeyHex, adminSignature, access, correlationId },
        "internal:channel-create",
      )) as { ok?: boolean; reason?: string; guidance?: string; relays?: unknown };
      if (reg?.ok !== true) {
        // Roll back an identity WE minted so a failed create leaves nothing behind — "nothing exists
        // yet" is the register step's contract.
        await rollbackMint(mintedHere);
        // 024-CREATE item 4: pass the register step's guidance up. It carries the directory's own
        // refusal detail (e.g. "admin signature does not verify" via registrationGuidance), so the
        // create step surfaces WHY the registration was refused instead of a generic register failure.
        // The create handler still supplies a fallback when the register step gave none.
        return { ok: false, reason: reg?.reason ?? "register_failed", guidance: reg?.guidance };
      }

      // The directory picks the channel's two relays from its pool and echoes them here. Fewer than
      // two DISTINCT relays is a registration we cannot honour — a channel with one relay is a single
      // point of failure — so it is treated as failed and the mint is rolled back, leaving nothing.
      const echoed = Array.isArray(reg.relays) ? reg.relays.filter((r): r is string => typeof r === "string") : [];
      const distinct = [...new Set(echoed)];
      if (distinct.length < 2) {
        await rollbackMint(mintedHere);
        return {
          ok: false, reason: "directory_returned_no_relays",
          guidance: "The directory did not return two distinct relays for this channel, so it was not created. Retry; if it persists, the directory's relay pool is short of relays.",
        };
      }
      return { ok: true, channelPubkeyHex, relays: distinct };
    },
    applyChannelConfig: (agentName, channelHex, cfg) =>
      recordChannelConfig({ logger, setChannelConfig }, agentName, channelHex, cfg),
    depositChannelInfo: (agentName, channelHex, correlationId) =>
      depositChannelInfo({ getPublisher: buildPublisher }, agentName, channelHex, correlationId),
  });

  /**
   * ⚠️ THE SUBSCRIBER HALF, AND IT NEEDS A SCHEDULE TO EXIST AT ALL. There is no inbound event for a
   * channel post — the relay holds a queue and waits to be asked — so a collector nobody calls is a
   * subscriber who receives nothing while every component reports healthy.
   */
  const subscriptions = new ChannelSubscriptionStore(deps.getDb(), logger);
  const inbox = new ChannelInboxStore(deps.getDb(), logger);
  const collector = new ChannelCollector({
    logger,
    subscriptions,
    inbox,
    fetch: (addr, req) => relay.fetch(addr, req),
    // 043-POSTERS: every poster lane, each from this member's own position in it.
    lanes: (addr, req) => relay.lanes(addr, req),
    lanePositions: new ChannelLanePositionStore(deps.getDb(), logger),
    // Every relay is asked and the NEWEST verified record wins, so one relay withholding a fresh
    // record cannot hide a revocation the other holds.
    revocations: async (relays, channelHex) => {
      const channelKey = new Uint8Array(Buffer.from(channelHex, "hex"));
      let best: { updated_at: number; revoked: ChannelPosterRevocation[] } | null = null;
      for (const addr of relays) {
        const raw = await relay.info(addr, channelKey).catch(() => null);
        if (raw === null) continue;
        const d = decodeChannelInfo(raw);
        if (!d.ok || Buffer.from(d.info.channel_pubkey).toString("hex") !== channelHex.toLowerCase()
          || !verifyChannelInfo(d.info)) continue;
        if (best === null || d.info.updated_at > best.updated_at) {
          best = { updated_at: d.info.updated_at, revoked: d.info.ext?.revoked ?? [] };
        }
      }
      return best?.revoked ?? [];
    },
    /**
     * ⚠️ **THE MEMBER PROVES MEMBERSHIP ON EVERY FETCH.** Signs with the fetch key derived from the
     * member's newest held group key, which the relay verifies against the admin's deposited fetch
     * pubkey; public → no auth, no key held → no auth + a warn. Extracted and unit-tested in
     * `channel-fetch-auth.ts`; this half only supplies the group keys the membership half stores.
     */
    fetchAuth: createChannelFetchAuth({ keysFor: (a, c) => subscriptions.keysFor(a, c), logger }),
    // The reader count is best-effort and never affects delivery, so declaring nothing costs only
    // the publisher's view of how many read a post. 019 records the membership this reads from.
    localAgentKeys: () => [],
    /**
     * ⚠️ NOT IMPLEMENTED, AND IT SAYS SO. Asking the publisher to re-deposit needs a session to the
     * publishing agent, which is 019's join path. Until then the OTHER RELAY is the whole repair —
     * `repairGaps` tries that first and usually closes the gap there. A silent no-op would let a
     * permanent gap look like one still being worked on.
     */
    requestRepair: (_agentId, channelHex, from, to) => {
      logger.warn("channel.repair.unavailable", {
        channel_pubkey: channelHex, from, to,
        impact: "neither relay holds these posts; asking the publisher directly needs the join path (019)",
      });
      return Promise.resolve();
    },
    // M16 032-NOTICES: a collect that advanced the position rings the content-free channel_posts
    // doorbell. 038-RETESTFIX Part C: the collector now hands the COUNT of posts actually delivered
    // (not after − before, which over-counted across a pruned floor) and the new `through` position.
    onDelivered: (agentId, channelHex, count, through, posters) => deps.notify.channelPosts(agentId, channelHex, count, through, posters),
    // 043-POSTERS: a poster's post names its writer — the local moniker, else a short key.
    posterName: (agentId, pubkeyHex) => {
      const a = deps.loadedAgents.find((x) => deps.resolveAgentId(x.name) === agentId);
      return a ? (deps.contactMoniker?.(a.name, pubkeyHex) ?? null) : null;
    },
  });

  const ticker = createChannelCollectTicker({
    logger, collector, subscriptions,
    isAgentOnline: deps.isAgentOnline,
    // 044-POSTERBELL: the admin no longer rings for poster posts — the POSTER rings itself the moment
    // a relay accepts (see ringPosterWake above), so 043 Part F's admin-side collection is gone.
  });
  ticker.start();

  return {
    stop: () => { ticker.stop(); },
    // M16 021-WAKE: what the doorbell calls. Exposed rather than wired here because the frame
    // arrives on the agent's signaling stream, which this module does not own.
    collectNow: (agentId: string) => ticker.collectNow(agentId),
    // M16 034-LIFECYCLE: the delete verb's prune step, over the WHOLE log. `pruneChannel` already
    // signs with the channel key (looked up by channelHex), so building the publisher with the
    // caller's admin name is enough — a channel with nothing in its log is `pruned: 0`, not an error.
    pruneAllPosts: async (agentName, channelHex) => {
      const publisher = buildPublisher(agentName);
      if (!publisher) return { pruned: 0, relays: [] };
      log.ensureChannel(channelHex);
      const head = log.head(channelHex);
      if (head.last_seq === null) return { pruned: 0, relays: [] };
      return publisher.pruneChannel(agentName, channelHex, head.last_seq);
    },
    // 041-HELPTRUTH Part B: the post count for an admin row in `cello channels`. Reads the log this
    // half owns; a channel with an empty log (or none) is `null`, never a fabricated 0.
    // `head` THROWS on a channel with no log row (created, never published), so the row is ensured
    // first, exactly as pruneAllPosts does above — without it one unpublished channel failed the whole
    // `cello channels` listing (live, 0.0.252).
    channelLastSeq: (channelHex) => {
      log.ensureChannel(channelHex);
      return log.head(channelHex).last_seq;
    },
    // 041-HELPTRUTH Part C: fetch the channel's info record from its relays, first that answers. A
    // relay fault on one is not fatal — the next is tried; all silent is `null` (the caller falls
    // back to the stored description).
    depositInfo: (agentName, channelHex) => depositChannelInfo({ getPublisher: buildPublisher }, agentName, channelHex),
    fetchInfo: async (relays, channelHex) => {
      const channelKey = new Uint8Array(Buffer.from(channelHex, "hex"));
      for (const addr of relays) {
        try {
          const record = await relay.info(addr, channelKey);
          if (record !== null) return record;
        } catch {
          // Try the next relay — a single relay being unreachable must not hide a record another holds.
        }
      }
      return null;
    },
    depositNotice: async (relays, record) => {
      let accepted = 0;
      for (const addr of relays) {
        try {
          const res = await relay.depositNotice(addr, record);
          if (res.ok) accepted += 1;
          else logger.warn("channel.notice.deposit_refused", { relay: addr, reason: res.reason });
        } catch (err: unknown) {
          logger.warn("channel.notice.deposit_failed", { relay: addr, reason: extractErrorMessage(err) });
        }
      }
      return accepted;
    },
    fetchNotices: async (relays, slot) => {
      const out: Uint8Array[] = [];
      for (const addr of relays) {
        try {
          const record = await relay.getNotice(addr, slot);
          if (record !== null) out.push(record);
        } catch {
          // One relay unreachable must not hide a notice the other holds.
        }
      }
      return out;
    },
    isAgentOnline: deps.isAgentOnline,
    ringMembers: (adminAgentName, channelHex, members) =>
      ringChannelMembers({ logger, signalingFor: (name) => deps.signalingFor(name) }, adminAgentName, channelHex, members),
  };
}
