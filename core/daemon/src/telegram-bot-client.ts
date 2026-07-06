/**
 * M8C-TGDOOR-1: the Telegram Bot API adapter — an interface + a real HTTP implementation, per the
 * M4+ rule ("every external dependency is behind an interface... never call it directly from
 * application code"). Tests inject a fake implementing the same interface; no real network.
 */

export interface TelegramUpdate {
  update_id: number;
  message?: {
    chat: { id: number | string };
    text?: string;
    message_id: number;
  };
}

export interface TelegramBotClient {
  /** Long-poll for updates since `offset` (the next update_id to fetch), waiting up to
   *  `timeoutSec` for one to arrive. Returns an empty array on timeout (not an error). */
  getUpdates(offset: number, timeoutSec: number): Promise<TelegramUpdate[]>;
  sendMessage(chatId: string, text: string): Promise<{ ok: boolean; error?: string }>;
}

export class HttpTelegramBotClient implements TelegramBotClient {
  constructor(private readonly botToken: string) {}

  async getUpdates(offset: number, timeoutSec: number): Promise<TelegramUpdate[]> {
    const url = `https://api.telegram.org/bot${this.botToken}/getUpdates?offset=${offset}&timeout=${timeoutSec}`;
    const res = await fetch(url);
    const body = (await res.json()) as { ok: boolean; result?: TelegramUpdate[]; description?: string };
    // Reviewer HIGH fix: fetch() does not throw on a non-2xx/ok:false Telegram response (e.g. a
    // revoked token returns HTTP 200 with {ok:false}) — treating that the same as "genuinely no
    // updates waiting" (an empty array) silently hides a misconfigured/dead bot forever, since the
    // poller's only error-observability path is its catch block, which this never reached. THROW
    // so the caller's catch/backoff/log path actually fires.
    if (!body.ok) {
      throw new Error(`telegram_get_updates_failed: ${body.description ?? "unknown_telegram_error"}`);
    }
    return body.result ?? [];
  }

  async sendMessage(chatId: string, text: string): Promise<{ ok: boolean; error?: string }> {
    const url = `https://api.telegram.org/bot${this.botToken}/sendMessage`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text }),
    });
    const body = (await res.json()) as { ok: boolean; description?: string };
    return body.ok ? { ok: true } : { ok: false, error: body.description ?? "unknown_telegram_error" };
  }
}
