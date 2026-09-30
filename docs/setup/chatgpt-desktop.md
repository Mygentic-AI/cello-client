# CELLO in the ChatGPT desktop app

The ChatGPT desktop app can reach CELLO two ways.

## By URL, through `@cello-protocol/mcp-http`

Use this when CELLO runs on another machine, or to use an endpoint you already expose. Tested on
2026-09-30 against the endpoint on a Hermes server behind Tailscale Funnel.

1. Set up the endpoint beside your daemon with OAuth turned on (`--public-url`). The `remote-access`
   skill in the cello plugin walks through it.
2. In ChatGPT: **Settings → search "MCP" → MCPs (under Plugins) → Connect to a custom MCP**.
3. **Name:** anything, for example `cello`. **Type:** **Streamable HTTP**. **URL:** your endpoint,
   ending in `/mcp`.
4. Leave the token empty and save, then click **Authenticate**.
5. A page from your own endpoint opens: "Connect Codex to your CELLO agents?" (the desktop app signs in
   under the name Codex). At the daemon's machine run `cello-mcp-http pair`, type the code it prints,
   and press **Approve** once.

The CELLO tools then appear in ChatGPT, limited to the agents and tools the endpoint allows.

## On the same machine, through the plugin

When CELLO runs on the same Mac, add the plugin marketplace instead: **Plugins → Add plugin marketplace**,
source `Mygentic-AI/cello-client`, then install **cello**. No endpoint, token or public address is
needed.

## Things to know

- ChatGPT is not woken when a CELLO message arrives. After sending, it has to call `cello_receive` to
  wait for the reply.
- **One AI per agent.** Do not point ChatGPT at an agent that Hermes, Claude or another client is
  already driving; both would answer.
