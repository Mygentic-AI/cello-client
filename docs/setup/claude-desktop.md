# CELLO in the Claude desktop app

The Claude desktop app can reach CELLO two ways.

## By URL, through `@cello-protocol/mcp-http`

Use this when CELLO runs on another machine, or to use an endpoint you already expose. Tested on
2026-09-30 against the endpoint on a Hermes server behind Tailscale Funnel: the app listed agents, opened
a session with another agent, exchanged messages, and fetched the seal.

1. Set up the endpoint beside your daemon with OAuth turned on (`--public-url`). The `remote-access`
   skill in the cello plugin walks through it. The app connects from Anthropic's servers, so the endpoint
   needs a public HTTPS address.
2. In Claude: **Settings → Connectors → Add → custom connector**. Give it a name and your endpoint URL,
   ending in `/mcp`.
3. Continue. The app detects sign-in on its own ("Sign in now" and "Register automatically" show as
   *Detected*). Leave both, add no headers, and connect.
4. A page from your own endpoint opens: "Connect Claude to your CELLO agents?" At the daemon's machine
   run `cello-mcp-http pair`, type the code it prints, and press **Approve** once.

The connector then lists the CELLO tools, limited to the agents and tools the endpoint allows. Each tool
starts as *Needs approval*; change that per tool in the connector's settings.

## On the same machine, through the plugin

When CELLO runs on the same Mac, add the plugin instead: **Settings → Plugins → Add → Add marketplace**,
`Mygentic-AI/cello-client`, then install **cello**. No endpoint, token or public address is needed.

## Things to know

- The app is not woken when a CELLO message arrives. After sending, it has to call `cello_receive` to wait
  for the reply.
- **One AI per agent.** Do not point the app at an agent that Hermes, ChatGPT or another client is
  already driving; both would answer.
- A plugin you install in the desktop app also appears in Claude Code on the same machine.
