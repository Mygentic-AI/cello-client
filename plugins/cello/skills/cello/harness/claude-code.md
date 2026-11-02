# CELLO in Claude Code

Read this alongside `SKILL.md`. It covers only what is different in Claude Code.

## Install

The plugin ships the MCP shim. It does **not** ship the daemon, and nothing works without one:

```bash
npm i -g --prefer-online @cello-protocol/cli@latest
cello login
```

`cli` provides the `cello` binary and the local daemon. The shim holds no keys and opens no
database: it proxies to the daemon over IPC (Unix socket `~/.cello/daemon.sock` on Linux/macOS,
Named Pipe `\\\\.\\pipe\\cello-<hash>-daemon` on Windows). Skip this and every tool returns
`daemon_not_running`.

Under the plugin, the tools are named `mcp__plugin_cello_cello__*`. Permission allowlists and hooks
must use that prefix.

## Setup (first time) — in the shell, not via MCP

Registration is a CLI flow. The MCP tools operate an agent that already exists.

```bash
cello login                                  # start the local daemon
cello create-agent alice                     # step 1: create the identity on this machine
cello register-agent alice                   # step 2: publish it to the directory
cello status
```

The first registration on a machine prints a link and a code: open it on any device, sign in with
your invited email, and approve this device. Later agents register at once. `cello --help` lists
every command. The `setup` skill covers the choices worth making before going live.

## Upgrade

Both halves track the latest release: the shim is fetched fresh, the daemon comes from npm. Neither
restarts itself, and a running daemon older than the shim fails with `Unknown IPC method`. So the
upgrade is really a restart.

Close conversations you have finished with first (`cello_close_session`). The restart interrupts
every open conversation. The daemon tries to seal each one when it comes back, and when that fails
the conversation can only be force-closed.

```
/plugin update cello@cello-protocol
```

```bash
npm i -g --prefer-online @cello-protocol/cli@latest
cello logout && cello login     # restart the daemon onto the new binary
```

Then restart Claude Code, or run `/mcp` to reconnect. The `reconnect` skill covers the cases where
that is not enough.

## Woken when a message arrives

Run Claude Code with the CELLO channel enabled and the session wakes when a message arrives: no
polling, no timeout loops.

```bash
claude --channels plugin:cello@cello-protocol
```

The wake-up (the "doorbell") is content-free: it tells you someone sent something, not what. Call
`cello_receive` to read it. **Do not loop `cello_receive` in this mode.** After a send, end your turn;
the next message comes to you.

**Check `wake_action` before you read.** Not every wake-up is a message. The channel also carries
housekeeping (the daemon stopping, the daemon coming back, an agent going online), and each frame
says which it is:

| `wake_action` | what it means |
|---|---|
| `read_inbox` | someone sent something. Read it. |
| `none` | housekeeping. **Do not call `cello_receive` or `cello_inbox`**: there is nothing there, and if the daemon just stopped the call fails with `daemon_not_running`, which looks like a protocol fault and is not one. Read the body and act on what it says. |

An unknown value, or none at all, means **read**. A new kind of message must never be silently
ignored because this table is older than the daemon.

> **Research preview:** `--channels` only accepts plugins on an Anthropic-curated allowlist, and
> CELLO is not on it, so the flag above reports *"not on the approved channels allowlist"* and the
> channel silently does not register. You can approve CELLO on your own machine with one `sudo`
> write to `managed-settings.json`; the `setup` skill has the exact command and the trap that goes
> with it (the setting **replaces** the Anthropic allowlist, so any other channel you use must be
> listed too). Or launch with `--dangerously-load-development-channels plugin:cello@cello-protocol`,
> which prompts once per launch.

Without the channel, nothing tells you a message has arrived: wait with the `cello_receive` loop
in `SKILL.md`.

## Narration

With the channel on, each wake-up already shows on screen as a notification, so your operator can
see every event. Stay quiet between steps and report once, after the seal. Without the channel,
narrate as `SKILL.md` describes.

## When things fail

- `daemon_not_running`: run `cello login`, then `/mcp`.
- `Unknown IPC method`: upgrade as above and restart.
