/**
 * The address-book SEAM — not its behavior.
 *
 * Eleven existing test files (m8c-contact-1, dod-settings-1, moniker-*, dod-contact-view-1, …)
 * already cover what these handlers DO, and they all pass unchanged across the extraction — that is
 * the behavior-preservation proof, and repeating it here would be noise.
 *
 * What was never pinned is the STRUCTURAL claim the extraction makes: the address book needs the
 * session store, a connection's agent selection, a logger, and a telegram-poller callback — and
 * NOTHING about sessions, seals, transport or ceremonies. Inside startDaemon's closure that claim
 * was unfalsifiable; every handler could reach all 73 shared locals whether it needed them or not.
 *
 * These tests make it falsifiable. They register the handlers against stubs, with NO daemon, NO
 * database, NO libp2p node — and drive them. If someone later reaches back into session or transport
 * state from an address-book handler, this file stops compiling or throws, and that is the point.
 */
import { describe, it, expect, vi } from "vitest";
import { registerContactHandlers, invalidPubkey, type ConnState } from "../contact-handlers.js";
import type { IpcHandler } from "../ipc-server.js";
import type { SessionNodeManager } from "../session-node-manager.js";

const PUBKEY = "a".repeat(64);

/** The entire surface of SessionNodeManager the address book actually touches. */
function makeStubStore() {
  return {
    addContact: vi.fn(),
    removeContact: vi.fn(() => true),
    listContacts: vi.fn(() => [{ pubkey: PUBKEY, moniker: "alice", tier: 2, added_at: 0 }]),
    getTier: vi.fn(() => 1),
    setContactTier: vi.fn(() => true),
    setContactMoniker: vi.fn(() => true),
    setContactAwayMessage: vi.fn(() => true),
    getSetting: vi.fn(() => null),
    getAllSettings: vi.fn(() => []),
    setSetting: vi.fn(),
    setTelegramSettings: vi.fn(),
  };
}

function harness(opts: { connState?: ConnState } = {}) {
  const handlers = new Map<string, IpcHandler>();
  const store = makeStubStore();
  const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
  const startTelegramPollerIfConfigured = vi.fn();
  const connState: ConnState = opts.connState ?? { currentAgent: "alice" };

  registerContactHandlers({
    handlers,
    sessionNodeManager: store as unknown as SessionNodeManager,
    getConnState: () => connState,
    // The daemon's real rule, in miniature: explicit wins, else the connection's selection.
    resolveCurrentAgent: (cs, explicit) => explicit ?? cs?.currentAgent ?? null,
    logger,
    startTelegramPollerIfConfigured,
  });

  const call = (name: string, params?: Record<string, unknown>) =>
    handlers.get(name)!(params, "conn-1");

  return { handlers, store, logger, startTelegramPollerIfConfigured, call };
}

describe("the address book runs with NO daemon — the seam is real", () => {
  it("registers all ten handlers against stubs alone: no DB, no libp2p node, no session runtime", () => {
    const { handlers } = harness();

    expect([...handlers.keys()].sort()).toEqual([
      "cello_contact_add",
      "cello_contact_list",
      "cello_contact_remove",
      "cello_contact_set_away",
      "cello_contact_set_moniker",
      "cello_contact_set_tier",
      "cello_set_moniker",
      "cello_settings_get",
      "cello_settings_set",
      "cello_telegram_set_token",
    ]);
  });

  it("adds a contact end-to-end through the stub store", async () => {
    const { store, call } = harness();

    const res = await call("cello_contact_add", { pubkey: PUBKEY }) as { ok: boolean; agent: string };

    expect(res.ok).toBe(true);
    expect(res.agent).toBe("alice");
    // TIER.KNOWN (2): an explicit add is a deliberate operator vouch — but NOT auto-accept.
    expect(store.addContact).toHaveBeenCalledWith("alice", PUBKEY, undefined, null, 2);
  });

  it("an explicit { agent } overrides the connection's selection — on every handler", async () => {
    const { store, call } = harness({ connState: { currentAgent: "alice" } });

    await call("cello_contact_add", { pubkey: PUBKEY, agent: "bob" });
    await call("cello_settings_set", { key: "away.default", value: "back later", agent: "bob" });

    expect(store.addContact).toHaveBeenCalledWith("bob", PUBKEY, undefined, null, 2);
    expect(store.setSetting).toHaveBeenCalledWith("bob", "away.default", "back later");
  });

  it("an UNKNOWN settings key is REFUSED, never persisted — a typo'd key would be a setting that silently never takes effect", async () => {
    const { store, call } = harness();

    const res = await call("cello_settings_set", { key: "auto_accept_tier", value: "3" }) as { ok: boolean; reason: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("invalid_key");
    expect(store.setSetting).not.toHaveBeenCalled();
  });

  it("no current agent and no explicit one: REFUSED, never guessed", async () => {
    const { store, call } = harness({ connState: { currentAgent: null } });

    const res = await call("cello_contact_add", { pubkey: PUBKEY }) as { ok: boolean; reason: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("no_current_agent");
    // The point of refusing: a guess would write someone else's address book.
    expect(store.addContact).not.toHaveBeenCalled();
  });

  it("the telegram token handler restarts the poller through the INJECTED callback", async () => {
    const { store, startTelegramPollerIfConfigured, call } = harness();

    const res = await call("cello_telegram_set_token", {
      bot_token: "123:abc",
      allowlisted_chat_id: "42",
    }) as { ok: boolean };

    expect(res.ok).toBe(true);
    expect(store.setTelegramSettings).toHaveBeenCalledWith("123:abc", "42");
    // The one piece of daemon lifecycle the address book touches — and it touches it through a
    // named callback, not by reaching into a closure.
    expect(startTelegramPollerIfConfigured).toHaveBeenCalledOnce();
  });
});

describe("invalidPubkey — a contact key must LOOK like a key, or the row can never match anyone", () => {
  it("refuses the `cello contact tier add` slip: 'tier' is not a pubkey, and nothing is stored", async () => {
    const { store, call } = harness();

    const res = await call("cello_contact_add", { pubkey: "tier" }) as { ok: boolean; reason: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("invalid_pubkey");
    expect(store.addContact).not.toHaveBeenCalled();
  });

  it("accepts a real 64-hex key, and refuses a 63- or 65-char one", () => {
    expect(invalidPubkey(PUBKEY)).toBeNull();
    expect(invalidPubkey("a".repeat(63))?.reason).toBe("invalid_pubkey");
    expect(invalidPubkey("a".repeat(65))?.reason).toBe("invalid_pubkey");
  });

  it("an ABSENT pubkey is not this check's business — the caller's missing_params owns it", async () => {
    const { call } = harness();
    expect(invalidPubkey(undefined)).toBeNull();

    const res = await call("cello_contact_add", {}) as { ok: boolean; reason: string };
    expect(res.reason).toBe("missing_params");
  });

  it("remove is the ESCAPE HATCH and stays ungated — a junk row must be deletable by name", async () => {
    const { store, call } = harness();

    // A contact whose pubkey is the literal text "tier" was written by the older, unvalidated code.
    // Gating remove would trap it forever: deleting it requires naming it.
    const res = await call("cello_contact_remove", { pubkey: "tier" }) as { ok: boolean };

    expect(res.ok).toBe(true);
    expect(store.removeContact).toHaveBeenCalledWith("alice", "tier");
  });
});
