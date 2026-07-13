/**
 * M8C-TGDOOR-1: the Telegram doorbell.
 *
 * A daemon-owned bot pushes discrete, CONTENT-FREE events (session request / message waiting /
 * state change) to one allowlisted operator chat. It is a convenience, never load-bearing: a
 * network hiccup backs off and retries rather than killing the poller, and an unconfigured
 * doorbell is INERT, not an error.
 *
 * Two invariants worth stating at the boundary, because the boundary is what enforces them now:
 *
 *   DOD-INV-CONTENTFREE — the doorbell sends a fixed label per event kind, NEVER message text.
 *     This module cannot leak conversation content because it is never given any: its whole
 *     dependency list is a logger, the stored settings, and a bot client.
 *   D6 — an inbound Telegram message from ANY chat is acknowledged and dropped. Nothing from
 *     Telegram enters a CELLO content path. Inside startDaemon that was a promise; here it is
 *     structural — there is no session-send seam in this module to abuse.
 */
import { HttpTelegramBotClient, type TelegramBotClient } from "./telegram-bot-client.js";
import type { Logger } from "./types.js";

export interface TelegramDoorbellDeps {
  logger: Logger;
  /** The persisted bot token + allowlisted chat id, or null when TGDOOR was never configured. */
  getTelegramSettings: () => { botToken: string; allowlistedChatId: string } | null;
  /** Test injection. Production passes nothing and a real HttpTelegramBotClient is built per token. */
  injectedClient?: TelegramBotClient | null;
}

export interface TelegramDoorbell {
  sendTelegramDoorbell: (agentName: string, sessionId: string, kind: "session_request" | "message_waiting" | "state_change", detail: string) => Promise<void>;
  clearTelegramRung: (agentName: string, sessionId: string) => void;
  startTelegramPollerIfConfigured: () => void;
  /** Shutdown: invalidate the running loop. It exits on its next generation check. */
  stopTelegramPoller: () => void;
}

export function createTelegramDoorbell(deps: TelegramDoorbellDeps): TelegramDoorbell {
  const { logger, getTelegramSettings, injectedClient } = deps;

  // M8C-TGDOOR-1: Telegram Mode 1 doorbell — a daemon-owned bot pushes discrete, content-free
  // events (session request / message-waiting / state change) to one allowlisted operator chat.
  // "NO channel machinery" (DoD) — this talks to the Telegram Bot API directly, unrelated to the
  // claude/channel MCP capability from Tiers 1-2. Inert until telegram_settings exist.
  let telegramBotClient: TelegramBotClient | null = injectedClient ?? null;
  let telegramChatId: string | null = null;
  let telegramBotToken: string | null = null; // tracked only to detect an actual token CHANGE
  // Generation counter, NOT a shared boolean — a boolean flip-to-false-then-true-again (e.g. a
  // settings update that restarts the poller) would let the OLD loop's `while` condition still
  // read true on its next check, running TWO concurrent loops. Each loop instance captures its
  // OWN generation at start and exits the instant the counter no longer matches (a new start, or
  // shutdown, both just bump it).
  let telegramPollerGeneration = 0;
  let telegramUpdateOffset = 0;
  // Coalescing: ring once for the FIRST message-waiting event since a session was last fully
  // read; cleared on read (cello_receive/since_seq advancing that session's watermark). Session
  // requests and state changes bypass this Set entirely — DoD says they always ring.
  const telegramRungUnread = new Set<string>();

  async function sendTelegramDoorbell(
    agentName: string,
    sessionId: string,
    kind: "session_request" | "message_waiting" | "state_change",
    detail: string,
  ): Promise<void> {
    if (!telegramBotClient || !telegramChatId) return; // TGDOOR not configured — inert, not an error
    if (kind === "message_waiting") {
      const rungKey = `${agentName}:${sessionId}`;
      if (telegramRungUnread.has(rungKey)) return; // already rung, still unread — coalesced
      telegramRungUnread.add(rungKey);
    }
    // DOD-INV-CONTENTFREE: `detail` is a fixed, content-free label per kind — NEVER message text.
    const text = `[${agentName} · ${sessionId.slice(0, 8)}] ${detail}`;
    try {
      const result = await telegramBotClient.sendMessage(telegramChatId, text);
      if (!result.ok) {
        logger.warn("telegram.doorbell.send.failed", { agentName, sessionId, kind, reason: result.error });
        return;
      }
      logger.info("telegram.doorbell.sent", { agentName, sessionId, kind });
    } catch (err: unknown) {
      logger.warn("telegram.doorbell.send.failed", { agentName, sessionId, kind, error: err instanceof Error ? err.message : String(err) });
    }
  }

  // Read clears the ring (DoD: "ring-once-until-read") — called wherever a receive advances a
  // session's read watermark, mirroring AWAY-1's own dedup-clear-on-attend pattern.
  function clearTelegramRung(agentName: string, sessionId: string): void {
    telegramRungUnread.delete(`${agentName}:${sessionId}`);
  }

  async function handleInboundTelegramUpdate(
    update: { message?: { chat: { id: number | string }; message_id: number } },
    client: TelegramBotClient,
  ): Promise<void> {
    const chatId = update.message?.chat?.id !== undefined ? String(update.message.chat.id) : undefined;
    if (!chatId) return;
    if (chatId !== telegramChatId) {
      // D6: any other chat is silently dropped — nothing enters CELLO content paths.
      logger.info("telegram.inbound.rejected", { chatId });
      return;
    }
    logger.info("telegram.inbound.acknowledged", { chatId });
    try {
      await client.sendMessage(
        chatId,
        "CELLO doesn't process messages here — this channel only sends you notifications. Use your CELLO client to reply.",
      );
    } catch (err: unknown) {
      logger.warn("telegram.inbound.ack.failed", { chatId, error: err instanceof Error ? err.message : String(err) });
    }
  }

  // Single long-lived getUpdates poller (DoD) — one in-flight loop per daemon; started once
  // settings exist, stopped on daemon shutdown. A network hiccup backs off and retries rather
  // than killing the poller (best-effort — the doorbell is a convenience, never load-bearing).
  // The client is a PARAMETER and must never be re-read from the shared, reassignable
  // telegramBotClient: a settings update mid-await would otherwise let a stale response from the OLD
  // client still be processed once (the generation check blocks the loop's NEXT iteration, not an
  // in-flight call), and stomp telegramUpdateOffset with the OLD bot's update_id numbering, which is
  // meaningless to a new token (Telegram scopes update_id per bot). Re-check the generation
  // immediately after EVERY await, before acting on its result or touching shared state.
  async function runTelegramPollerLoop(myGeneration: number, myClient: TelegramBotClient): Promise<void> {
    let myOffset = telegramUpdateOffset;
    while (telegramPollerGeneration === myGeneration) {
      try {
        const updates = await myClient.getUpdates(myOffset, 25);
        if (telegramPollerGeneration !== myGeneration) break; // superseded while awaiting — drop stale results
        for (const u of updates) {
          myOffset = u.update_id + 1;
          telegramUpdateOffset = myOffset;
          if (u.message) void handleInboundTelegramUpdate(u, myClient);
        }
      } catch (err: unknown) {
        if (telegramPollerGeneration !== myGeneration) break; // superseded — don't retry under a dead generation
        logger.warn("telegram.poller.error", { error: err instanceof Error ? err.message : String(err) });
        await new Promise((r) => setTimeout(r, 2000)); // back off before retrying
      }
    }
  }

  // Always bumps the generation (invalidating any prior loop, which exits on its next check) and
  // starts a fresh one — correct both for the first start AND a settings-change restart.
  function startTelegramPollerIfConfigured(): void {
    const settings = getTelegramSettings();
    if (!settings) return; // not configured — TGDOOR stays inert
    // Reviewer MEDIUM fix: reset the offset on an actual token/chat CHANGE — a prior bot's
    // update_id numbering is meaningless to a new one (Telegram scopes it per bot token).
    if (telegramBotToken !== settings.botToken || telegramChatId !== settings.allowlistedChatId) {
      telegramUpdateOffset = 0;
    }
    telegramBotToken = settings.botToken;
    telegramChatId = settings.allowlistedChatId;
    const client = injectedClient ?? new HttpTelegramBotClient(settings.botToken);
    telegramBotClient = client;
    telegramPollerGeneration += 1;
    void runTelegramPollerLoop(telegramPollerGeneration, client);
    logger.info("telegram.poller.started", {});
  }
  function stopTelegramPoller(): void {
    telegramPollerGeneration += 1;
  }

  return { sendTelegramDoorbell, clearTelegramRung, startTelegramPollerIfConfigured, stopTelegramPoller };
}
