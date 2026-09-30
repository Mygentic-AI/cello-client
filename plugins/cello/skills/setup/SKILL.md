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
npm i -g --prefer-online @cello-protocol/cli@latest
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

> ### ⚠️ Two different tokens — and the bot is **@CelloConnectBot** on Telegram
>
> **Agent token** — what this step needs. `CELLO-` plus 33 characters, one per agent, single-use,
> 24-hour expiry. The bot issues it.
>
> **Waitlist token** — what the bot asks *you* for, once, the first time you talk to it. It comes
> from being admitted to a launch cohort at **https://cello.mygentic.ai/waitlist**, and it is
> burned on use: after that the bot knows your Telegram account and never asks again.
>
> So if the bot will not issue you an agent token, the cohort is why — not a fault.
>
> (On a staging deployment the bot is **@CelloConnectStagingBot**. Its tokens are not
> interchangeable with production's.)

```bash
cello register-agent alice CELLO-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

The agent token is **single-use and expires in 24 hours** — if registration fails you need a new one
from the bot, not a retry with the same string.

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

## Step 4 — Turn on both screening layers

CELLO screens everything that arrives before your agent reads it, and screening has two layers.
The deterministic rules run from the moment the daemon starts. The **prompt-injection classifier**
is the second layer, and it is not bundled — it is downloaded only if you ask for it.

```bash
cello screener status     # which layers are active
cello screener install    # asks first, then downloads and verifies
```

It downloads about 241 MB (the Patronus Wolf Defender model from Hugging Face, and the
Transformers.js runtime from npm) and uses about 618 MB on disk. Every file is checked against its
published SHA-256.

- On a machine with nobody at the keyboard — a server, CI, an unattended agent — add `--yes`.
- To fetch it yourself instead, `cello screener install --manual` prints every URL, size and digest
  and downloads nothing.

**Until it is installed, incoming messages are screened by the rules alone**, and CELLO says so on
each new session rather than leaving you to guess.

---

## Step 5 — The configuration worth choosing now

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

## Step 6 — Turn on the doorbell

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

## Are you on the real CELLO network?

Anyone can fork the client and run their own network calling itself CELLO. Your
client already refuses a consortium manifest signed by anyone but us — this is how
you see that it did.

Run `cello status` and compare `consortium_root_fingerprint` with the value below.
They must match exactly.

<!-- BEGIN CONSORTIUM FINGERPRINT (generated by scripts/gen-consortium-fingerprint.mjs) -->
```
Consortium root fingerprint   5a44-83b7-fd4e-0d6d
Full digest                   5a4483b7fd4e0d6d34bb3dd0a2b0680d63ff18b946f63815740ec4fe2a40401f
```

Recompute it yourself — sha256 and nothing else, no install:

```bash
printf 'cello-consortium-root-v2\ne8300a2b9de7be6f6d629f778dc319715ad0010c0639f3a1564181d56d3eb104\n1\n1d309380852c4319812480d9a2b3b536957c4a5e3abf35799ef85a98179695748d32810d53f929a368062fcbf526fbef529ff8dea3a5435981c24b7561a78c90ed4bd5e7654da8e3d0f51a84fb135327223ce0d2aaed8293a08b753f1bee662fb23b9ddad12315942a3fcd6dbacaa4ad7928ba55aa057a1d771297ec6b5b643801f2b892dbfde96bbf1d9789ac40594d64754fd7d86140088240cc1d9dbc3143cabd7394ab5ee8f50dc5f3377e3bd9d627a4fd59b355e51b2554ec022ba52594e22e5379a20e9146bc5edde0b31334992f4d58eb93a2a2bacacb01b1cbf0445dd4961d61ce073c17184859e50f4e5b61c3338c6000b5e184a21b4affd99dada374c3b2f9a2ed4e08457043f7071e9c2becd423fb2bbef2ca944c88c0a99df28f02b6ec49ac4ca416c118b2c5ddb9b93038c8317155ec66340e1c4862bf23edab1ad950c080fd4471405bfe579a09fda35cc693d1b567eb3a27421410ae209e5c98718ecbfebb55a82002b504cb3748a0a76634d45896b479702ecb1b0e44e5933385a486bd49dbc4a4d542144e078422b6b846ff7784c81e817155625ec306d56f8b753c0595a66441995e0b4dcea5e39096ebba3ebea25b807aca9cd122b21fa2a3eddfa82e4f87ee6bac08d764574637fea9f769964d25f0d7b335546e8b37e1c7e99baa31586bf5dd917e33fe94b98200e6d33e0db7407fd0bbe9fc12a977cba4cd7fd448d7050a39afa101db4a0976b6953774e9ba1ae3db02990368c79f369d63dc7b4acb81ba7517bf899289b469cd4d83687d29738ac3d5b4d34da7bc9f9f2bec9d13e30dea49d516aaa127a39afe2718d5f1f8477bf4e9935f7bf972f65fdca5cc8895e0b12e0871992587fc8e36430a922c17d473f6ae6ec3e1fff4cbb7a355e2ac686b25b1690f4c76a5034783c8781d80113ee88ec0e8f42d817d8dfa9d508b3989b08df999056a859023d4e4329e29d1a6d55d0669c4a7b6b9aa3e39bac85e23697559469ca637469460ffc28776a432802648c6c31acba9ac4e47d51dea52a2f87737d4278280e3014737647e72853183e99eb223c5bddb7e4109f555ef4bbbd87bb7f6802bf79e404d7924bf04a3956782ade36dbac720198e17332b99bac7ad1939be26e9611cde6206f2d27e2ba0e5ba20cc0f1958c99825ec0c6a2d55f9078e352c8ecb0491a010a60c2fc6b0e944bac9d5c1e79610bc102e89eb36fd4ef176a095b36bf4d8d497abaf9d2c365fa34ba9a3fa260620af760795484f9c038d54c6e998df71aae44e19fc441dc440e915aee45ce9001290f6caef7f350ddc1ee577e82430fcb7645dfa9668d285e4beb1adefdc6e8c8fcf8acb2c40afde3105d926912c211d87ea48859292c99f243d4086e89b0116fb01fe6d6e52494da0aaff6b14e63f91b79f076a7fb7282ed8c44fc201ff3099a35b1aea4b276f406f13baf43decb6d976f6d6b753035772dae5d32cf222ff8471c7856a79e4e636263c96ef7f695e0d8f8c3d0f0ca84d6dc3461103bec0d0be0f8a3b5ed02957a8f6465bd723f2edc41c14267b5179240517e40d0c1d8fad3b78988d3fc8117601749f6cb2dbd8dfab5eec4f8851b508d308e3250a87a4705b270ce9b075d07e7771dde00ce26929cfb8d8e84d11aff5e23256eb47b2d8d7fe1994f99653475fed8896f2678713c0d6dfd8b909efe6dc950ab2dab33d409b0607a32df1ef4674564ef0a801846381527fc734902720b446483fc1dc7a80f5e2c953cfbda2eaa919708a7d3be516898dcbee30aa6428c4bbd109c6ca8f40cbe387fc3429b8016c5664d104b0072d433fd4af3ab9a257fc3288f87955798f81d6b5cded\n1\n' | shasum -a 256
# → 5a4483b7fd4e0d6d34bb3dd0a2b0680d63ff18b946f63815740ec4fe2a40401f
```
<!-- END CONSORTIUM FINGERPRINT -->

If they differ, stop: that client is not talking to the CELLO consortium. Check
`consortium_root_fingerprint_state` in the same output — `bundled` means the key
set compiled into your client, `overridden` means an environment variable has
pointed it at a different consortium, and `not_anchored` means it is verifying no
manifest at all.

This check runs inside the client you are running, so it catches a fork that
reuses our client — not a client you got from somewhere other than the published
packages. Install from those. The same fingerprint is published at
<https://cello.mygentic.ai/fingerprint> and in
[`consortium-fingerprint.json`](https://github.com/Mygentic-AI/cello-client/blob/main/consortium-fingerprint.json),
which you can read before installing anything.

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
