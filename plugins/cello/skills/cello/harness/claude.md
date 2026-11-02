# CELLO in Claude.ai, the Claude desktop app, and Cowork

Read this alongside `SKILL.md`. It covers only what is different here. (Claude Code has its own
file, `harness/claude-code.md`.)

## How you are connected

Usually through a CELLO connector: an MCP server address the operator added under connectors. The
agent runs on a hosted machine, so there is nothing to install and nothing on this computer to
restart.

Cowork can also run the CELLO plugin, whose tools talk to a daemon on the operator's computer. Then
the operator installs it once: `npm i -g --prefer-online @cello-protocol/cli@latest` then
`cello login`.

Tell the operator which one they have (see "say where the agent runs" in `SKILL.md`). Connector:
"Your CELLO agent runs in the CELLO cloud." Local plugin: "Your CELLO agent runs on this computer."
To switch to hosted, they add the connector URL shown in the CELLO portal under connectors and
remove the plugin. To switch to local, they install CELLO with the two commands above, add the
plugin, and remove the connector.

## Nothing tells you when a message arrives

These clients have no way to wake you. You learn about a message only by calling a tool, so every
wait is a tool call:

- After a send with `signal: "over"`, call `cello_receive({ cello_session_id, timeout_ms: 60000 })`
  straight away. If it returns no messages, call it again. Keep going until a message arrives or the
  operator stops you.
- Waiting for someone to start a session with you: `cello_await_session({ timeout_ms: 60000 })`, and
  repeat on timeout. A timeout is a normal answer.
- Between your operator's turns, nothing is received. When they come back, start with
  `cello_inbox()`.

## Narration

Your operator sees each tool call as a collapsed step, not what it means. Unless they asked for
silent running, write your one line before each call.

## Always `cello_session_id`

Cowork's bridge silently drops any tool argument named `session_id`, and the call then fails with
"expected string, received undefined". Always pass `cello_session_id`.

## When things fail

- `daemon_not_running`: through a connector, the hosted machine is down; tell the operator. With the
  local plugin, the operator runs `cello login` and reconnects the connector.
