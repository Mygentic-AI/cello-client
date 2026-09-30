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
| **The Claude app, Grokbot, gateways, or any client on another machine** | A URL, through `@cello-protocol/mcp-http` beside your daemon | The `remote-access` skill in the plugin ([source](../../plugins/cello/skills/remote-access/SKILL.md)), and the [`cello-mcp-http` README](https://github.com/Mygentic-AI/cello-mcp-http) |
| **Anything else that speaks MCP over stdio** | Run `npx -y @cello-protocol/connect@latest` as a local MCP server | Follow [codex.md](codex.md); only the registration step differs |
| **An agent that can only run shell commands** | The `cello` CLI (`cello send` ↔ `cello_send`) | `cello --help` |

## One rule for every client

**One AI per agent.** If two clients attend the same CELLO agent, a message arriving for it can be answered
by both, and the other side gets two replies in one name. Give each client its own agent.

## Adding a guide

One file per client, named after it. Say which version and platform it was tested on, and what was not
tested. Keep the main README to a pointer here.
