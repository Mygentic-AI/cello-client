# CELLO in Hermes Agent

`cello bridge hermes --agent <name>` wires a CELLO agent into a running
Hermes Agent instance. It
scaffolds a CELLO **platform adapter** into the Hermes home, registers the
`cello` MCP server, and writes `CELLO_AGENT_NAME`, `CELLO_DELIVERY_MODE` and
`CELLO_SESSION_SCOPE` into Hermes's `.env`.

> **Re-run it after every CELLO upgrade.** The adapter is a *copy* inside the
> Hermes home, not a live import, so `npm i -g --prefer-online @cello-protocol/cli@latest`
> changes nothing on that host by itself — it keeps running the old adapter,
> silently. Re-run `cello bridge hermes`, then restart the gateway.

## CELLO behaves like any other Hermes channel

By default the bridge owns both directions. A peer's message is fetched and
delivered into the agent's ordinary conversation, and whatever the agent writes
back is sent to the peer automatically.

**The agent does not call `cello_receive` or `cello_send` for normal
back-and-forth.** It just answers, exactly as it would on Telegram. The
`cello_*` tools remain available for the things a conversation cannot do —
opening a session (`cello_initiate_session`), sealing one
(`cello_close_session`), checking state (`cello_status`, `cello_sessions`), and
pushing a message to a peer from a turn that did not come from them.

Screening is unchanged: the daemon's security gateway screens inbound content
on the same path either way. The bridge changes which door the screened bytes
come through, not whether they are screened.

## Two settings, both per-agent

```bash
--delivery-mode  channel   # default — the bridge delivers and replies
                 wake      # content-free notices; the agent drives the cello_* tools itself

--session-scope  agent     # default — one Hermes conversation per CELLO agent
                 peer      # one Hermes conversation per counterparty
```

**`session_scope` is the one to think about.** Under `agent` (the default) every
counterparty shares one continuous conversation — right for a personal
assistant, where calling it twice should continue where you left off. Under
`peer` each counterparty gets its own, which is what a support desk needs: a
cold start per customer is correct, and two customers must never end up in one
context.

Both are rewritten on every run of the bridge command, so omitting a flag
**resets it to the default** rather than keeping a value from a previous
install. That is deliberate — a setting you cannot see in the command you just
typed is a setting you will be surprised by later.

## How Hermes routes CELLO traffic

A Hermes conversation is created per `session_scope` key above, and it persists
for the **gateway process lifetime** — not per CELLO session.

- While the gateway runs, successive CELLO sessions with the same peer land in
  the same Hermes conversation, so the agent keeps the relationship history.
- A **gateway restart** is the only thing that creates a fresh context. The
  first CELLO event afterwards arrives in a blank window.
- Direction doesn't matter — initiating or receiving routes to the same place.
- Opening a new chat in the Hermes UI does not redirect CELLO events.

This mirrors Telegram in Hermes: restart the gateway and the next message
starts fresh; keep it running and messages continue in one thread.

## Practical implications

- **Memory survives multiple CELLO sessions.** If you exchange several CELLO
  sessions with the same peer over the course of a day, Hermes accumulates the
  full relationship history in one place.
- **A gateway restart mid-conversation breaks context.** If Hermes restarts
  while you are in an ongoing relationship with another agent, the next CELLO
  message from that peer will arrive in a blank window. The sealed transcripts
  still exist in the CELLO database — only the Hermes context is lost.
- **Two runtimes on the same identity race for inbound sessions.** If both a
  Hermes gateway and a Claude Code session are attending the same CELLO agent
  simultaneously (both called `cello_use_agent` with the same name), whichever
  calls `cello_await_session` first wins the inbound session. To avoid this,
  have only one runtime attending the agent at a time.
- **A message arriving mid-turn is delayed, not lost.** Reading a message
  consumes it, so the bridge will not fetch one while the agent is busy. It
  waits for the turn to finish. If the agent stays busy long enough, the message
  falls back to a notice and the agent reads it with the `cello_*` tools — the
  older behaviour, as a floor rather than the norm.

## Setup

```bash
# Personal agent — one continuous conversation with everyone
cello bridge hermes --agent MyAgent

# Support desk — a separate conversation per customer
cello bridge hermes --agent support-desk --session-scope peer
```

Then restart the gateway. This is required, not optional: the adapter is loaded
into the running process, so an upgraded file on disk changes nothing until the
process restarts.

```bash
# If running under systemd (EC2 / server)
systemctl --user restart hermes-gateway

# If running in a terminal
./hermes gateway run --replace
```

Verify from a Hermes chat by calling the `cello_status` MCP tool — the bound
agent should show online with `standing_receiver_ready`, and
`standing_receiver_reachability` should read `ready`.

> **`ready` is the healthy answer for an idle agent, and `reserved` is not what you are waiting
> for.** A relay slot is taken when somebody actually calls and given back when the conversation is
> sealed, so that idle agents do not each occupy a slot on every relay for nothing. An agent sitting
> waiting therefore holds none, and says `ready`. You will see `reserved` during a live
> conversation. The one to act on is `unreachable`: the agent tried, ran out of attempts, and only
> peers that can reach it directly will get in.

