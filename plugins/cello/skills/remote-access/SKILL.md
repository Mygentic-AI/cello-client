---
name: remote-access
description: Use when an MCP client can't start a local process and can only be given a URL — the Claude app's custom connectors, Grokbot, a Hermes-style gateway, or Claude Code on a different machine from the CELLO daemon. Covers running @cello-protocol/mcp-http beside the daemon, limiting which agents and tools it exposes, giving it a public HTTPS address (Tailscale Funnel recommended), and connecting a client by header token or by OAuth sign-in with a pairing code.
---

# CELLO over a URL — `@cello-protocol/mcp-http`

## What it is, and when you need it

The `cello` plugin starts the CELLO tools as a local process on the machine where the daemon runs. That
works for Claude Code on the same machine. It does not work for a client that can only be given a URL:

- the **Claude app** (custom connectors),
- **Grokbot** and similar hosted assistants,
- a **Hermes-style gateway**,
- **Claude Code on another machine** than the daemon.

For those, run `@cello-protocol/mcp-http` on the daemon's machine. It serves the same `cello_*` tools,
with the same parameters, over MCP Streamable HTTP at one URL ending in `/mcp`. It forwards every call to
the daemon over `~/.cello/daemon.sock`. It holds no keys and keeps no conversation state.

If the client and the daemon are on the same machine and the client can start a local process, you do not
need this. Use the `cello` plugin.

## 1. Start it beside the daemon

```bash
openssl rand -hex 32 > ~/.cello/mcp-http.token && chmod 600 ~/.cello/mcp-http.token
npx -y @cello-protocol/mcp-http --port 8787 \
  --token-file ~/.cello/mcp-http.token \
  --agents <agent-name> \
  --tools-file ~/.cello/mcp-http.tools
```

Run `npx -y @cello-protocol/mcp-http --help` for every flag.

- **`--agents`** — the only agents this endpoint may act as, by name or pubkey, comma-separated. Each must
  exist on the daemon or it will not start. A caller asking for any other agent is refused
  `agent_not_permitted`. Always set it: leaving it out allows every agent on the daemon.
- **`--tools-file`** — one `cello_*` tool name per line; `*` means every tool; `-name` removes one; `#`
  lines are comments. A good start:
  ```
  *
  -cello_config_set
  -cello_settings_set
  -cello_set_agent_offline
  -cello_contact_set_tier
  ```
  Those four change reachability or the security layer's settings; keep them at your own terminal. A
  name the endpoint does not know stops it at startup, with the name in the error.
- **The token** is required. Whoever has it can use every tool you allowed, as the agents you allowed.

It listens on `127.0.0.1` only. Nothing outside the machine can reach it yet.

Run it as a service so it survives restarts, started after the CELLO daemon (with `--agents` set, it
refuses to start if it can't reach the daemon to check the names).

## 2. Give it a public HTTPS address

A hosted client like the Claude app connects from its own servers, so the endpoint needs a public HTTPS
URL. Choose by who is allowed to read your traffic — it carries your agents' message text.

| Option | Who can read the traffic | Address | Use when |
|---|---|---|---|
| **Tailscale Funnel** (recommended) | Only your machine. Tailscale's servers pass the encrypted stream through. | Stable, `https://<machine>.<tailnet>.ts.net`, free on the personal plan | Almost always, including a laptop behind a home router |
| **Your own TLS** (`--tls-cert`, `--tls-key`, public `--host`) | Only your machine | Your domain | You run a server with a public IP and a domain |
| **ngrok** (free tier) | **ngrok can read your messages** — it decrypts at its servers | Stable free domain | Only if that is acceptable to you |

Cloudflare's quick tunnel does not support the streaming this endpoint uses, and its stable tunnels
decrypt at Cloudflare. Not recommended.

**Tailscale Funnel:**

```bash
curl -fsSL https://tailscale.com/install.sh | sh     # Linux; on macOS use the open-source build, not the App Store one
sudo tailscale up                                     # prints a sign-in link; sign in with a personal account
sudo tailscale funnel --bg 8787                       # prints the public URL; the first time it links to a page to enable Funnel
```

Your endpoint is then `https://<machine>.<tailnet>.ts.net/mcp`. Check it is locked:
`curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<machine>.<tailnet>.ts.net/mcp` must print `401`.

## 3. Connect the client

**A client that can send a header** (Claude Code, Hermes, most gateways): give it the URL and
`Authorization: Bearer <token>`. For Claude Code there is a plugin that does this from two environment
variables:

```bash
export CELLO_MCP_URL=https://<machine>.<tailnet>.ts.net/mcp
export CELLO_MCP_TOKEN=$(cat ~/.cello/mcp-http.token)
/plugin marketplace add Mygentic-AI/cello-mcp-http
/plugin install cello-remote@cello-remote
```

**A client that only takes a URL** (the Claude app): turn on OAuth sign-in by adding `--public-url` with
your public origin (no `/mcp`):

```bash
npx -y @cello-protocol/mcp-http --port 8787 --token-file ~/.cello/mcp-http.token \
  --agents <agent-name> --tools-file ~/.cello/mcp-http.tools \
  --public-url https://<machine>.<tailnet>.ts.net
```

Then:

1. In the Claude app, add a custom connector with the URL `https://<machine>.<tailnet>.ts.net/mcp` and
   press Continue.
2. A page from your own endpoint opens: "Connect Claude to your CELLO agents?" It asks for a pairing code.
3. On the machine where CELLO runs: `npx -y @cello-protocol/mcp-http pair`. It prints a code like
   `K7QM-2XPD`, good for 10 minutes and one use.
4. Type the code and approve. The CELLO tools appear in Claude, limited to the agents and tools you allowed.

The code exists only in a file on your machine that your user alone can read, so only someone at that
machine can approve a sign-in. Five wrong tries cancel the code. The app's access renews itself; there is
no token in any URL.

**Managing sign-ins:**

```bash
npx -y @cello-protocol/mcp-http clients            # which apps are signed in
npx -y @cello-protocol/mcp-http revoke             # sign every app out
npx -y @cello-protocol/mcp-http revoke <client-id> # sign one app out
```

A revoked app is refused on its next request and must pair again.

## What the limits do and do not cover

`--agents` and `--tools-file` bound this endpoint. They do not bound other programs on the same machine
that can open the daemon socket — your user account is the boundary there, as it is for the daemon.
