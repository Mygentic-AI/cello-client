---
name: reconnect
description: Use when CELLO worked before and has stopped — daemon_not_running, ipc_connection_lost, Unknown IPC method, tools missing or returning errors, after rebooting the machine, or after upgrading the CLI or the plugin. Covers the restart and upgrade paths. Not for first-time setup.
---

# CELLO — reconnect after a reboot or an upgrade

CELLO stopping is almost always one of three things, and they present identically ("my cello tools
stopped working"). Identify which before doing anything.

| What you see | What it is | Go to |
|---|---|---|
| `daemon_not_running` | the daemon isn't up — usually a reboot | [Reboot](#after-a-reboot) |
| `ipc_connection_lost`, tools error after a daemon restart | Claude Code is holding a dead socket | [Stale connection](#after-restarting-the-daemon-mid-session) |
| `Unknown IPC method` | shim and daemon are different versions | [Upgrade](#after-an-upgrade) |
| No `cello_*` tools at all | the plugin isn't loaded | [Plugin missing](#no-cello-tools-at-all) |

If CELLO has **never** worked on this machine, this is the wrong skill — use the `setup` skill.

---

## After a reboot

**The daemon does not autostart.** There is no launchd job and no systemd unit. Every boot, it is
gone and your agents are offline — nobody can reach them.

```bash
cello login
cello status
```

`cello login` starts the daemon and brings the agents back online. Confirm with:

```bash
cello agents      # every agent you expect: state "unattended" or "online", standing_receiver_ready true
```

`standing_receiver_ready: true` is the load-bearing field. An agent that is `online` without it will
not accept inbound sessions, and callers get **`home_node_reports_no_receiver`** with nothing in your
logs to explain it.

That reason is named for exactly this: the directory has no live receiver registered for you, which
is NOT the same as your agent being offline — and your own `cello_status` will look perfectly
healthy while it happens. Reconnecting the daemon, below, is what re-registers it.

Then reconnect Claude Code to the daemon — see [stale connection](#after-restarting-the-daemon-mid-session).

## After restarting the daemon mid-session

Claude Code's MCP connection points at the socket that existed when the session started. Restart the
daemon underneath a running session and the shim holds a dead handle: tools are still listed, and
every call fails.

```
/mcp
```

Reconnecting the server from `/mcp` is the fix. If tools still fail after that, **restart Claude
Code** — a socket replaced while the session was live sometimes cannot be recovered in place.

Order matters when both are down: **daemon first, then Claude Code.** Starting them together races,
and the session attaches to a socket that is about to be replaced.

## After an upgrade

The shim and the daemon are two halves of one node talking over the socket. They must move together.
A version gap surfaces as `Unknown IPC method` — that error means skew, not a missing feature.

Upgrade both, then restart both:

```bash
npm install -g @cello-protocol/cli@latest
cello logout && cello login
```

```
/plugin update cello@cello-protocol
```

Then restart Claude Code so the new shim is spawned.

`cello logout` waits until the daemon has actually exited, so it is safe to chain. Do not skip it —
`npm install` replaces the binary on disk but the *running* daemon is still the old one until it
restarts.

Check what you actually have:

```bash
cello --version
claude plugin list | grep cello
```

## No cello tools at all

The plugin isn't loaded in this session.

```bash
claude plugin list          # is cello@cello-protocol present and enabled?
```

- **Not listed** → `claude plugin install cello@cello-protocol`
- **Listed but disabled** → `claude plugin enable cello`
- **Listed and enabled but no tools** → plugins load at startup; restart Claude Code, or `/reload-plugins`

## The doorbell stopped waking the session

Messages arrive but the session doesn't react until you call `cello_receive` yourself.

The channel is registered per launch, by flag. It is not sticky — a session started without the flag
has no doorbell, no matter what is installed.

```bash
claude --channels plugin:cello@cello-protocol
```

Read the startup banner. It tells you exactly what happened:

- *"messages from plugin:cello@cello-protocol inject directly in this session"* → working.
- *"not on the approved channels allowlist"* → **the channel did not register** and no events will
  arrive. During the research preview `--channels` only accepts plugins on an Anthropic-curated
  allowlist. Two ways past it: launch with
  `--dangerously-load-development-channels plugin:cello@cello-protocol` (a confirmation screen each
  launch), or have an admin add `{ "marketplace": "cello-protocol", "plugin": "cello" }` to
  `allowedChannelPlugins` in managed settings. **Setting `allowedChannelPlugins` replaces the
  Anthropic allowlist entirely** — any other channel you use (Telegram, Discord, iMessage) must be
  listed there too or it stops registering.

In channels mode, do **not** poll `cello_receive`. The doorbell comes to you; after a `cello_send`
with `signal: "over"`, read once when the event fires.

---

## Do not do this

**Never `pkill -f cello-daemon`.** It kills every daemon on the machine, including agents you did not
mean to touch, and it does not wait for a clean exit. Use `cello logout`, which does.

**Never assume a reboot lost your data.** Keys, sessions, transcripts, and seals live in the
encrypted database under `CELLO_DIR` (default `~/.cello`). `cello login` picks them all back up. If
an agent looks empty after a restart, suspect a changed `CELLO_DIR` before suspecting data loss.
