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
   * Step 1: register `<name>` as a channel administered by `adminPubkeyHex`, through the existing
   * registration path. Returns the channel's own pubkey — the key a subscriber verifies posts
   * against and the key `config`/`info-set` are addressed by.
   */
  registerChannel: (opts: {
    name: string;
    preAuthToken: string;
    adminPubkeyHex: string;
    access: ChannelAccess;
    correlationId: string;
  }) => Promise<{ ok: true; channelPubkeyHex: string } | { ok: false; reason: string; guidance?: string }>;
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
    // never spend a registration.
    const name = params?.["name"];
    if (typeof name !== "string" || name.length === 0) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'name': the channel's local identity label, the same thing register-agent takes." };
    }
    const access = params?.["access"];
    if (access !== "public" && access !== "open" && access !== "invite_only") {
      return { ok: false, reason: "bad_access", guidance: "Pass 'access': public (anyone can read), open (anyone may ask to join) or invite_only." };
    }
    const rawRelays = params?.["relays"];
    const relays = Array.isArray(rawRelays) ? rawRelays.filter((r): r is string => typeof r === "string") : [];
    if (relays.length < 2 || !Array.isArray(rawRelays) || relays.length !== rawRelays.length) {
      return { ok: false, reason: "bad_relays", guidance: "Pass 'relays': two relay multiaddrs this channel publishes to. Two is the design — one is a single point of failure, and the subscriber takes the union of both." };
    }
    // The token falls back to CELLO_PREAUTH_TOKEN on the CLI, exactly as register-agent does; by the
    // time it reaches here it is an explicit field.
    const preAuthToken = params?.["preAuthToken"];
    if (typeof preAuthToken !== "string" || preAuthToken.length === 0) {
      return { ok: false, reason: "missing_preauth_token", guidance: "Creating a channel requires a 'preAuthToken' issued by the CELLO Operations Agent, the same kind register-agent takes." };
    }
    const adminPubkeyHex = deps.agentPubkey(adminName);
    if (adminPubkeyHex === null) {
      return { ok: false, reason: "no_current_agent", guidance: `Agent '${adminName}' has no key on this daemon, so it cannot administer a channel.` };
    }

    const correlationId = randomUUID();
    logger.info("channel.create.started", { correlationId, name, admin_pubkey: adminPubkeyHex, access });

    // ─── Step 1: register the channel identity ───
    const registered = await deps.registerChannel({ name, preAuthToken, adminPubkeyHex, access, correlationId });
    if (!registered.ok) {
      logger.warn("channel.create.failed", { correlationId, step: "register", reason: registered.reason });
      return {
        ok: false, step: "register", reason: registered.reason,
        // Step 1 failing means nothing exists yet — there is no channel to finish by hand.
        guidance: registered.guidance ?? "The channel was not registered, so nothing was created. Fix the cause and run 'cello channel create' again.",
      };
    }
    const channelHex = registered.channelPubkeyHex;

    // ─── Step 2: record relays + access locally ───
    const configured = deps.applyChannelConfig(adminName, channelHex, {
      access, relays, guidance: "", retention_seconds: DEFAULT_RETENTION_SECONDS,
    });
    if (!configured.ok) {
      logger.warn("channel.create.failed", { correlationId, step: "config", reason: configured.reason });
      return {
        ok: false, step: "config", reason: configured.reason,
        guidance: `The channel is registered but its relays and access were not recorded. Finish it by hand: 'cello channel setup ${channelHex} ${access} ${relays.join(" ")}'.`,
      };
    }

    // ─── Step 3: deposit the info record ───
    const deposited = await deps.depositChannelInfo(adminName, channelHex);
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
