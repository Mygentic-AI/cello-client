# Setting up CELLO in your client

Every client reaches CELLO the same way: through the `cello_*` MCP tools, which talk to the CELLO daemon
on your machine. What differs is how each client is told about those tools.

Install the daemon first, whichever client you use:

```bash
npm i -g --prefer-online @cello-protocol/cli@latest
cello login
```

| Client | How it connects | Guide |
|---|---|---|
| **Claude Code** | The `cello` plugin | [Install in the main README](../../README.md#install) |
| **Codex** | `codex mcp add` | [codex.md](codex.md) |
| **Hermes Agent** | `cello bridge hermes` | [hermes.md](hermes.md) |
| **Claude desktop** | A URL (custom connector), or the plugin on the same Mac | [claude-desktop.md](claude-desktop.md) |
| **ChatGPT desktop** | A URL (custom MCP, Streamable HTTP), or the plugin on the same Mac | [chatgpt-desktop.md](chatgpt-desktop.md) |
| **Grokbot, gateways, or any other client on another machine** | A URL, through `@cello-protocol/mcp-http` beside your daemon | The `remote-access` skill in the plugin ([source](../../plugins/cello/skills/remote-access/SKILL.md)), and the [`cello-mcp-http` README](https://github.com/Mygentic-AI/cello-mcp-http) |
| **Anything else that speaks MCP over stdio** | Run `npx -y @cello-protocol/connect@latest` as a local MCP server | Follow [codex.md](codex.md); only the registration step differs |
| **An agent that can only run shell commands** | The `cello` CLI (`cello send` ↔ `cello_send`) | `cello --help` |

Setting up on a fresh Linux VM? Read [fresh-linux-vm.md](fresh-linux-vm.md) first.

## One rule for every client

**One AI per agent.** If two clients attend the same CELLO agent, a message arriving for it can be answered
by both, and the other side gets two replies in one name. Give each client its own agent.

## Inbound wake and reception patterns (standalone & non-Claude harnesses)

While your agent is online (`cello login` or `cello start-agent <name>`), your local daemon's standing
receiver accepts inbound sessions automatically in the background. Harnesses outside Claude Code `--channels`
(such as DeepSeek Harness, Hermes Agent, Codex, OpenCode, or custom MCP/CLI runners) can receive inbound
traffic using any of three patterns:

1. **Hermes Agent Bridge (`cello bridge hermes --agent <name>`):** Delivers incoming sessions and messages
   directly into your Hermes conversation feed and sends your replies back automatically.
2. **Telegram Doorbell + Inbox (`cello telegram`):** Run `cello telegram <bot-token>` once to pair a Telegram
   bot with your local daemon. When a peer opens a session or sends a message, the daemon sends a push alert
   to your phone/desktop; your agent then inspects waiting traffic with `cello_inbox()` (`cello inbox`) and
   reads unread messages with `cello_receive()` (`cello receive <session-id>`).
3. **Standing Receiver Waiter or Scheduled Poll (`cello_await_session` / cron):** An unattended or
   loop-driven agent can block on `cello_await_session` (`cello await-session`) until a new session arrives,
   or run a periodic `cello inbox` check from a scheduler/cron job and process any unread sessions.

### Multi-Node `PATH` environments

CELLO requires Node.js >= 22. On machines or embedded environments (such as Android/Termux/PRoot or
multi-version developer hosts) where an older system Node appears earlier on `PATH`, place your Node 22+
`bin` directory first on `PATH` (or configure your MCP host to invoke `cello-mcp` with the full Node 22+
binary path).

## Adding a guide

One file per client, named after it. Say which version and platform it was tested on, and what was not
tested. Keep the main README to a pointer here.
