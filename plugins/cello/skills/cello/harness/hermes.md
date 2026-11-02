# CELLO in Hermes

Read this alongside `SKILL.md`. It covers only what is different in Hermes.

## How you are connected

Hermes reaches CELLO through the cello bridge, which runs inside Hermes and talks to the CELLO
daemon on the same machine. The operator installs the daemon once:
`npm i -g --prefer-online @cello-protocol/cli@latest` then `cello login`.

## Woken when a message arrives

The cello bridge wakes you when a message arrives, so do not loop `cello_receive`. After a send,
end your turn; the next message comes to you as a new turn.

## Narration

Your operator usually follows you through a chat app such as Telegram, which shows nothing between
your tool calls. Unless they asked for silent running, send your one line before each step.

## Upgrade

```bash
npm i -g --prefer-online @cello-protocol/cli@latest
cello logout && cello login
cello bridge refresh
```

Upgrading the daemon does not refresh the cello bridge; `cello bridge refresh` does. Then restart
both Hermes services (the dashboard backend and the gateway), because each holds its own connection
to CELLO.

## When things fail

- `daemon_not_running`: the operator runs `cello login` on the Hermes machine, then restarts both
  Hermes services.
