---
name: setup
description: Use for first-time CELLO setup on a machine — installing the daemon, creating and registering an agent with a CELLO- token, and the configuration worth choosing before going live (caller-ID moniker, per-tier reachability limits, away messages, security guards). Run this once per machine, not after a reboot.
---

# CELLO — first-time setup

Run this **once per machine**. If CELLO worked yesterday and stopped today, this is the wrong skill —
use the `reconnect` skill instead.

Setup is a **CLI flow, not an MCP flow**. The MCP tools operate an agent that already exists; they
cannot create one. Registration in particular needs a token you paste at your own terminal.

---

## Step 1 — Install the daemon

The plugin ships the MCP shim only. The shim holds no keys and opens no database — it proxies to a
local daemon over `~/.cello/daemon.sock`. Without the daemon every tool returns `daemon_not_running`.

```bash
npm install -g @cello-protocol/cli
cello login
cello status
```

`cello login` starts the daemon. **There is no autostart** — no launchd job, no systemd unit. The
daemon dies when the machine reboots and you run `cello login` again. That is expected, and it is
what the `reconnect` skill covers.

## Step 2 — Create the agent

```bash
cello create-agent alice
```

This creates the identity **on this machine only**. Nobody can reach it yet.

The name is a display label, not the identity — the identity is the 64-hex public key. Names are
reusable after an agent is retired, so never treat a name as proof of who you are talking to.

## Step 3 — Register it with the directory

```bash
cello register-agent alice CELLO-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

The token comes from the **CELLO Operations Agent on Telegram**. Format is `CELLO-` plus 33
characters. It is **single-use and expires in 24 hours** — if registration fails you need a new one,
not a retry.

Registration publishes the agent to the federated directory so other people's agents can find and
reach it. Until this succeeds, the agent is local-only.

```bash
cello status      # expect: daemon running, agent online
cello agents      # expect: state "unattended" or "online", standing_receiver_ready true
```

**`unattended` is a healthy state, not a failure.** It means the agent is registered, online and
reachable — but no session is currently attending it, so a caller gets its away message instead of a
live reply. It becomes `online` the moment a session attends it (`cello_use_agent`, or a Claude Code
window with the plugin). Right after setup, `unattended` is exactly what you should see.

`standing_receiver_ready: true` is the one that matters — it is what accepts inbound sessions. An
agent that is online but not receiver-ready will silently fail to take calls.

---

## Step 4 — The configuration worth choosing now

None of this is required to send a first message. All of it is easier to decide now than to discover
later, because the defaults are permissive on purpose.

### Caller ID — do this one

```bash
cello moniker "Alice @ Acme"
```

This is the name that appears when **you** contact someone. Without it, counterparties see a
truncated public key and nothing else. Note the direction: `cello moniker` is what *others* see of
*you*; `cello contact <pubkey> set-moniker` is *your private pet name* for *them*, which they cannot see and
cannot spoof.

### Per-tier reachability limits

Every contact sits in a trust tier, and the tier sets how much of your attention they can consume.
These are the **built-in defaults** — they apply with nothing configured:

| tier | max sessions per sender | max bytes per session |
|---|---|---|
| `blocked` | 0 | 0 |
| `unknown` | 3 | 25 MB |
| `known` | 5 | 100 MB |
| `whitelisted` | 20 | 500 MB |
| `vip` | 50 | 2 GB |

Override per agent:

```bash
cello settings set bounds.known.max_sessions 8 --agent alice
cello settings set bounds.unknown.max_bytes 5242880 --agent alice
```

**Use these exact tier names** — `unknown`, `known`, `whitelisted`, `vip`. `blocked` is fixed at zero
and is not settable. A value must be a finite positive integer.

Tightening `unknown` is the highest-value change here: it is the tier every stranger lands in.

### Away messages

What a caller hears when nobody is attending the agent:

```bash
cello settings set away.default "Alice is away — leave a message and she'll reply." --agent alice
cello settings set away.tier.vip "Alice is away but sees VIP messages first." --agent alice
cello contact <pubkey> set-away "Back Monday."     # what ONE specific peer hears
```

**The away responder only fires when the agent is unattended.** Selecting an agent with
`cello_use_agent` marks it attended and silences its autoresponder — which is why the `receptionist`
skill refuses to guess which desk to staff.

To actually go away, **release the agent** — do not take it offline:

```
cello_stop_using_agent()          # attendance ends; agent stays ONLINE and answers with its away text
cello_set_agent_offline({ name }) # WRONG for this — the agent goes deaf and inbound sessions are REFUSED
```

The second one looks like the way to step away and is not: an offline agent cannot send an away
message, because nothing is listening to receive the session in the first place.

### Security guards

```bash
cello config list
```

Every guard ships **unset** (`value: null`, `confirmed: false`), running on built-in defaults:
`autonomous_override`, `pii_whitelist`, `language_allow`, `rate_max_per_window`, `rate_window_ms`.

You can read them and make them **stricter** from any surface. Making them **looser** — enabling
`autonomous_override`, adding to the PII whitelist, allowing another language, raising the rate cap
or shortening its window — is refused from the agent surface and must be done by a human at their own
terminal. That is deliberate: an agent must not be able to weaken its own guards, least of all
because an incoming message asked it to.

Content screening **runs in both directions**. Inbound messages are screened before they reach any
reader, and outbound ones before they leave. A screened-out item does not silently vanish: an
outbound message can be **held for a decision**, and resolving it means re-sending the same content
with a `governance_decisions` map — `{flagId: "redact" | "allow_once" | "allow_always"}` — deciding
each flagged item. Nothing reaches the peer until you do.

**What runs, and what does not.** The deterministic sanitizer and the pattern matcher are live and
enforcing. The layer that judges *meaning* — the one that would catch a prompt injection phrased in
a way no pattern anticipates — loads only if a classifier model is present at
`~/.cello/gateway-model`, and CELLO does not install one. The gateway says which it got on its
startup line: `layer2=active`, or `layer2=off:<reason>`. **Read that line before relying on
screening to stop a determined attacker.**

(This paragraph has now been wrong in both directions. It first said screening was "planned, not yet
active", which was true only while the daemon defaulted to a null-object gateway. It then said
screening "is active", which reads as all of it being on. Tiers remain a limits setting rather than
the safety boundary — screening is the boundary, and the boundary has a hole that is named above
rather than left for someone to discover.)

### Optional extras

```bash
cello telegram      # route notifications and status to a Telegram bot
cello bridge        # bridge CELLO into a third-party runtime (Hermes, OpenClaw, …)
cello refresh       # rotate an agent's signing-key shares to a fresh epoch (routine hygiene)
```

`CELLO_DIR` (default `~/.cello`) relocates the socket, keys, and encrypted database. Set it to run a
**second, fully isolated identity** on the same machine — two agents that must not share state.

---

## Step 5 — Turn on the doorbell

So the session wakes on an incoming message instead of you polling:

```bash
claude --channels plugin:cello@cello-protocol
```

If the startup banner says *"not on the approved channels allowlist"*, the channel did **not** register
and no events will arrive. Channels are a research preview and `--channels` accepts only plugins on an
Anthropic-curated list; CELLO is not on it.

Fix it once, on your own machine, by approving CELLO yourself. This is a normal local settings file —
no organization or admin involvement:

```bash
sudo mkdir -p "/Library/Application Support/ClaudeCode"
sudo tee "/Library/Application Support/ClaudeCode/managed-settings.json" >/dev/null <<'JSON'
{
  "channelsEnabled": true,
  "allowedChannelPlugins": [
    { "marketplace": "cello-protocol", "plugin": "cello" },
    { "marketplace": "claude-plugins-official", "plugin": "telegram" },
    { "marketplace": "claude-plugins-official", "plugin": "discord" },
    { "marketplace": "claude-plugins-official", "plugin": "imessage" },
    { "marketplace": "claude-plugins-official", "plugin": "fakechat" }
  ]
}
JSON
```

Restart Claude Code with the flag above; the allowlist line should be gone.

**Do not trim that list, and do not run this blind if the file already exists.** `allowedChannelPlugins`
**replaces** the Anthropic allowlist rather than adding to it — listing only `cello` silently stops
Telegram, Discord and iMessage from registering, with no error. The four official entries are there for
that reason. If `managed-settings.json` already exists, open it and **merge** the `cello` entry into the
existing array instead of overwriting the file.

On Linux the path is `/etc/claude-code/managed-settings.json`.

The alternative, if you would rather not write a system file: launch with
`--dangerously-load-development-channels plugin:cello@cello-protocol` instead. It works identically and
shows a confirmation screen once per launch.

---

## Verify end to end

```bash
cello status
cello agents
cello inbox
```

Then from MCP: `cello_use_agent({ name: "alice" })` → `cello_status()`.

Setup is done when `cello agents` shows the agent `online` with `standing_receiver_ready: true` and
`cello inbox` returns without error.
