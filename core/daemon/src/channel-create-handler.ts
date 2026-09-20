/**
 * M16 024-CREATE — `cello_channel_create`, the ONE IPC method that brings a channel into existence.
 *
 * Sixteen orders built everything a channel does — registering it (004), recording its relays
 * (018's config) and depositing its info record (info-set) — and only a test harness ever called
 * the first of those. A person or agent could not create a channel. This handler composes the three
 * existing steps IN ORDER, in-process, so a crash between them cannot leave a half-made channel:
 *
 *   1. register `<name>` as a channel administered by the CURRENTLY SELECTED agent;
 *   2. record its two relays and access locally (the same code `cello_channel_config` runs);
 *   3. deposit its info record (the same code `cello_channel_info_set` runs).
 *
 * A channel costs a full registration, same as an agent — the pre-auth token is the same kind
 * `cello register-agent` takes. There is no partial success: if a step fails, the answer names WHICH
 * step and the command that finishes the job by hand. A register failure means nothing exists yet.
 *
 * The three steps are INJECTED (`registerChannel`, `applyChannelConfig`, `depositChannelInfo`) so
 * this composition is unit-testable without a live directory — a real registration runs a DKG
 * against the consortium, which is the enforcer's job. `wireChannelPublishing` binds them to the
 * real registration handler, config store and publisher.
 */
import { randomUUID } from "node:crypto";
import type { Logger } from "./types.js";
import type { ChannelAccess } from "@cello-protocol/protocol-types";
import { DEFAULT_RETENTION_SECONDS } from "./channel-config-store.js";

type Handler = (params: Record<string, unknown> | undefined, connectionId: string) => Promise<unknown>;

export interface ChannelCreateDeps {
  handlers: Map<string, Handler>;
  logger: Logger;
  /** The daemon's single agent-selection rule — the admin is the currently selected agent. */
  resolveCurrentAgent: (connectionId: string, explicitAgent?: string) => string | null;
  /** The K_local pubkey of a local agent this daemon holds, or null. Used for the admin's pubkey. */
  agentPubkey: (agentName: string) => string | null;
  /**
   * Step 1: register `<name>` as a channel administered by `adminName`/`adminPubkeyHex`, through the
   * existing registration path. NO token — the admin's Ed25519 signature over the channel's pubkey
   * is signed inside this step and is the whole basis of the right. Returns the channel's own pubkey
   * (the key a subscriber verifies posts against, addressed by `config`/`info-set`) AND the two
   * relays the directory picked from its pool — nobody types a relay.
   */
  registerChannel: (opts: {
    name: string;
    adminName: string;
    adminPubkeyHex: string;
    access: ChannelAccess;
    correlationId: string;
  }) => Promise<{ ok: true; channelPubkeyHex: string; relays: string[] } | { ok: false; reason: string; guidance?: string }>;
  /** Step 2: the SAME code `cello_channel_config` runs. */
  applyChannelConfig: (
    agentName: string,
    channelHex: string,
    cfg: { access: ChannelAccess; relays: string[]; guidance: string; retention_seconds: number },
  ) => { ok: true } | { ok: false; reason: string; guidance?: string };
  /** Step 3: the SAME code `cello_channel_info_set` runs. */
  depositChannelInfo: (
    agentName: string,
    channelHex: string,
    correlationId?: string,
  ) => Promise<{ ok: true } | { ok: false; reason: string; guidance?: string }>;
}

export function registerChannelCreateHandler(deps: ChannelCreateDeps): void {
  const { handlers, logger } = deps;

  handlers.set("cello_channel_create", async (params, connectionId) => {
    // The admin is the currently selected agent — no flag to pick a different one.
    const adminName = deps.resolveCurrentAgent(connectionId, params?.["agent"] as string | undefined);
    if (adminName === null) {
      return { ok: false, reason: "no_current_agent", guidance: "Name the agent that will administer the channel, or select one with cello_use_agent." };
    }

    // Everything is validated up front, BEFORE the registration is attempted — a bad argument must
    // never run a registration.
    const name = params?.["name"];
    if (typeof name !== "string" || name.length === 0) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'name': the channel's local identity label, the same thing register-agent takes." };
    }
    const access = params?.["access"];
    if (access !== "public" && access !== "open" && access !== "invite_only") {
      return { ok: false, reason: "bad_access", guidance: "Pass 'access': public (anyone can read), open (anyone may ask to join) or invite_only." };
    }
    // ⚠️ A CHANNEL TAKES NO TOKEN, AND CARRIES NO RELAY. Its right to register is the admin's
    // signature — the admin is already a registered agent, which paid the identity cost. Refuse a
    // token loudly so nobody carries the old habit forward (the first cut demanded one; that was the
    // planner's invention, not decision 31). The relays are the directory's to pick, not the caller's.
    if (params?.["preAuthToken"] !== undefined || params?.["relays"] !== undefined) {
      return {
        ok: false, reason: "channel_needs_no_token",
        guidance: "A channel takes NO pre-auth token and NO relay argument. The admin agent's identity is the basis of the right, and the directory picks the two relays. Run: cello channel create <name> <access> [--guidance <text>].",
      };
    }
    const adminPubkeyHex = deps.agentPubkey(adminName);
    if (adminPubkeyHex === null) {
      return { ok: false, reason: "no_current_agent", guidance: `Agent '${adminName}' has no key on this daemon, so it cannot administer a channel.` };
    }

    const correlationId = randomUUID();
    logger.info("channel.create.started", { correlationId, name, admin_pubkey: adminPubkeyHex, access });

    // ─── Step 1: register the channel identity ───
    // No token: the admin signs the channel's pubkey (inside registerChannel), and the directory
    // returns the two relays it picked from its pool.
    const registered = await deps.registerChannel({ name, adminName, adminPubkeyHex, access, correlationId });
    if (!registered.ok) {
      // 024-CREATE item 4: log the register step's guidance too — it carries the directory's own
      // refusal detail (e.g. "admin signature does not verify"), so the failure event says WHY, not
      // just a generic reason label.
      logger.warn("channel.create.failed", { correlationId, step: "register", reason: registered.reason, guidance: registered.guidance });
      return {
        ok: false, step: "register", reason: registered.reason,
        // Step 1 failing means nothing exists yet — there is no channel to finish by hand.
        guidance: registered.guidance ?? "The channel was not registered, so nothing was created. Fix the cause and run 'cello channel create' again.",
      };
    }
    const channelHex = registered.channelPubkeyHex;
    const relays = registered.relays;

    // ─── Step 2: record the directory's relays + access locally ───
    // The channel's description travels with the info record (step 3) — an empty one would deposit a
    // channel nobody looking it up can tell apart, so it is a real parameter, not a placeholder.
    const guidanceText = typeof params?.["guidance"] === "string" ? (params["guidance"] as string) : "";
    const configured = deps.applyChannelConfig(adminName, channelHex, {
      access, relays, guidance: guidanceText, retention_seconds: DEFAULT_RETENTION_SECONDS,
    });
    if (!configured.ok) {
      logger.warn("channel.create.failed", { correlationId, step: "config", reason: configured.reason });
      return {
        ok: false, step: "config", reason: configured.reason,
        guidance: `The channel is registered but its relays and access were not recorded. Finish it by hand: 'cello channel setup ${channelHex} ${access} ${relays.join(" ")}'.`,
      };
    }

    // ─── Step 3: deposit the info record ───
    const deposited = await deps.depositChannelInfo(adminName, channelHex, correlationId);
    if (!deposited.ok) {
      logger.warn("channel.create.failed", { correlationId, step: "info_set", reason: deposited.reason });
      return {
        ok: false, step: "info_set", reason: deposited.reason,
        guidance: `The channel is set up but its description was not published, so subscribers cannot discover it yet. Finish it by hand: 'cello channel info-set ${channelHex}'.`,
      };
    }

    logger.info("channel.create.completed", { correlationId, channel_pubkey: channelHex, admin_pubkey: adminPubkeyHex, access });
    return { ok: true, channel_pubkey: channelHex, name, access, relays, admin_pubkey: adminPubkeyHex };
  });
}
