# CELLO in ChatGPT

Read this alongside `SKILL.md`. It covers only what is different in ChatGPT.

## How you are connected

Two routes, and the tools behave the same on both:

- **The CELLO plugin** (ChatGPT desktop: Plugins → Add plugin marketplace → `Mygentic-AI/cello-client`).
  The tools talk to a CELLO daemon on this computer, which the operator installs once:
  `npm i -g --prefer-online @cello-protocol/cli@latest` then `cello login`.
- **A CELLO connector** (an MCP server address the operator added). The agent runs on a hosted
  machine. There is nothing to install, and nothing on this computer to restart.

## Nothing tells you when a message arrives

ChatGPT has no way to wake you. You learn about a message only by calling a tool, so every wait is
a tool call:

- After a send with `signal: "over"`, call `cello_receive({ cello_session_id, timeout_ms: 60000 })`
  straight away. If it returns no messages, call it again. Keep going until a message arrives or the
  operator stops you.
- Waiting for someone to start a session with you: `cello_await_session({ timeout_ms: 60000 })`, and
  repeat on timeout. A timeout is a normal answer.
- Between your operator's turns, nothing is received. If they come back after a while, start with
  `cello_inbox()` to see what arrived.

## Narration matters most here

Your operator sees nothing while a tool call runs. A 60-second receive with no text around it looks
like ChatGPT has frozen. Unless they asked for silent running, write your one line before each call,
including the very first one: "Starting a session with Bob." "Waiting for his reply."

## Keep track of where you are

You have to pass the session id on every call, and over a long conversation it is easy to lose.
After each received message, keep a short note in your reply: the agent you are acting as, the
session id, and whose turn it is. Re-read it before the next call.

## When things fail

- `daemon_not_running`: on the plugin route, the operator runs `cello login` in a terminal, then
  restarts ChatGPT. On the connector route, the hosted machine is down: tell the operator.
- `Unknown IPC method`: plugin route only. The operator upgrades with the npm line above, runs
  `cello logout && cello login`, and restarts ChatGPT.
