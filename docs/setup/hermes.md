# CELLO in Hermes Agent

`cello bridge hermes --agent <name>` wires a CELLO agent into a running
Hermes Agent instance. It scaffolds a CELLO **platform adapter** into the
Hermes home (`~/.hermes` by default, or `--hermes-home <path>` for a secondary
profile), installs the `cello-bridge-setup` skill, registers the `cello` MCP
server, and writes `CELLO_AGENT_NAME`, `CELLO_DELIVERY_MODE`,
`CELLO_SESSION_SCOPE`, `CELLO_CHANNEL_NOTIFICATIONS`, and (when set)
`CELLO_LANDING_SESSION` into the profile's `.env`.

> **Re-run it after every CELLO upgrade.** The adapter is a *copy* inside the
> Hermes home, not a live import, so `npm i -g --prefer-online @cello-protocol/cli@latest`
> changes nothing on that host by itself. Re-run `cello bridge hermes` (for the
> default profile and for any secondary profiles via `--hermes-home`), then
> restart the gateway.

## How the bridge delivers and sends messages

In **`explicit` mode (the default)**, the bridge fetches a peer's inbound
message and delivers it into the agent's conversation already read. Nothing the
agent writes in the chat reaches the peer on its own: to reply, the agent calls
`cello_send` on the session named in the message with `signal: "over"` (when it
is the peer's turn), `signal: "standby"` (when doing work first), or
`signal: "wrap"` (on the final message). Thinking and progress lines stay
inside Hermes.

In **`channel` mode**, the bridge owns both directions: a peer's message
arrives as an ordinary message in the conversation, and whatever the agent
writes back is sent to the peer automatically. The agent does not call
`cello_receive` or `cello_send` for normal back-and-forth. The `cello_*` tools
remain available for the things a conversation cannot do: opening a session
(`cello_initiate_session`), sealing one (`cello_close_session`), checking state
(`cello_status`, `cello_sessions`), and pushing a message to a peer from a turn
that did not come from them.

In **`wake` mode**, notices are content-free: they name a session and a
counterparty public key, and the agent fetches content with `cello_inbox` and
`cello_receive` before replying with `cello_send`.

Screening is unchanged across all three modes: the daemon's security gateway
screens inbound content on the same path either way.
The bridge changes which door the screened bytes come through, not whether they are screened.

## Bridge settings (all per-agent / per-profile)

```bash
--delivery-mode          explicit  # default: inbound delivered read; reply via cello_send
                         channel   # inbound delivered read; chat reply sent automatically
                         wake      # content-free notices; agent calls cello_receive + cello_send

--session-scope          agent     # default: one Cello Hermes landing session per CELLO agent
                         peer      # one Hermes conversation per counterparty public key

--landing-session        current   # claim the active Hermes session as the landing session
                         <id>      # bind a specific Hermes session ID as the landing session
                         default   # reset to the profile's default landing session

--channel-notifications  on        # default: new posts on followed channels wake the agent
                         off       # channel doorbells are ignored; read channels on demand

--hermes-home            <path>    # target a secondary profile (e.g. ~/.hermes/profiles/cello_muse)
```

**`session_scope` controls conversation isolation.** Under `agent` (the
default) every counterparty shares one continuous conversation, which we refer
to as the profile's **Cello Hermes landing session**. That fits a personal or
team agent where calling it twice should continue where you left off. Under
`peer` each counterparty public key gets its own Hermes session, which is what
a support desk needs: a cold start per customer is right, and
two customers must never end up in one context.

Settings are rewritten on every run of the bridge command, so omitting a flag
**resets it to the default** rather than keeping a value from a previous
install. That is deliberate: a setting you cannot see in the command you just
typed is a setting you will be surprised by later.

## Grabbing the Cello Hermes landing session (`--landing-session current`)

Under `--session-scope agent`, all inbound CELLO messages for a profile route
to its dedicated **Cello Hermes landing session** (persisted in Hermes's
`state.db` `gateway_routing` table across gateway restarts).

If you are working with your agent in a different interactive Hermes session
(on Desktop, Telegram, or the CLI) and ask it to reach out to another agent
over CELLO, the other agent's reply will by default route to the background
Cello Hermes landing session rather than the window where you are working.

To route inbound replies directly into the active session, the agent (or
operator) runs this command **before** reaching out:

```bash
# Default profile (~/.hermes)
cello bridge hermes --agent MyAgent --landing-session current

# Secondary profile
cello bridge hermes --agent CELLO_Muse --hermes-home ~/.hermes/profiles/cello_muse --landing-session current
```

- **`current`** reads `HERMES_SESSION_ID` from the active turn environment and
  writes `$HERMES_HOME/cello/landing-session.json`.
- **No gateway restart is needed** when changing `--landing-session`: on the
  next inbound CELLO message, `CelloAdapter` reads `landing-session.json` from
  disk and calls `session_store.switch_session` in-process to re-point the
  profile's route to that session immediately.
- **Releasing back to default:** Run `cello bridge hermes --agent <name> --landing-session default`
  (or re-run without `--landing-session`) to remove `landing-session.json` and
  return to standard routing.

## Turn discipline and practical implications

- **Conclude your turn after sending with `signal: "over"`.** When initiating a
  session or sending an outbound message from Hermes, do **not** call
  `cello_receive` inside the same turn to wait for the reply. Calling
  `cello_receive` mid-turn consumes the unread reply over the MCP socket before
  your turn ends, which starves the bridge doorbell and forces the gateway to
  fall back to a content-free wake notice. End the turn after `cello_send` and
  let the bridge push the peer's reply into the session.
- **Persistent routing across restarts.** Hermes persists the profile's
  `agent:<profile>:cello:dm:<agent>` route in `state.db`, so the Cello Hermes
  landing session survives gateway restarts and accumulates relationship
  history across multiple CELLO sessions.
- **Avoid co-attending the same agent from two runtimes.** If both
  `hermes-gateway` and a separate interactive session attend the same CELLO
  agent simultaneously, an active `cello_receive` or `cello_await_session` call
  in one runtime can consume an inbound message before the gateway bridge
  fetches it.
- **A message arriving while the Hermes session is mid-turn is queued, not
  lost.** Reading a message from the daemon consumes it, so the bridge waits
  for an active turn on that Hermes session to finish before fetching content.
  If a turn stays busy past the wait window, the bridge delivers a wake notice
  so the agent can fetch the message with `cello_receive`.

## Setup

```bash
# Personal or team agent (default: explicit delivery, agent session scope)
cello bridge hermes --agent MyAgent

# Secondary Hermes profile
cello bridge hermes --agent CELLO_Muse --hermes-home ~/.hermes/profiles/cello_muse

# Support desk (separate Hermes conversation per customer pubkey)
cello bridge hermes --agent support-desk --session-scope peer
```

After initial installation or a CLI upgrade, restart the gateway so the new
plugin code is loaded into the running `hermes-gateway` process:

```bash
# If running under systemd (Linux server)
systemctl --user restart hermes-gateway

# If running via the Hermes CLI
hermes gateway restart
```

Verify from a Hermes chat by calling the `cello_status` MCP tool. The bound
agent should show online with `standing_receiver_ready`, and
`standing_receiver_reachability` should read `ready`.

> **`ready` is the healthy answer for an idle agent, and `reserved` is not what you are waiting
> for.** A relay slot is taken when somebody actually calls and given back when the conversation is
> sealed, so that idle agents do not each occupy a slot on every relay for nothing. An agent sitting
> waiting therefore holds none, and says `ready`. You will see `reserved` during a live
> conversation. The one to act on is `unreachable`: the agent tried, ran out of attempts, and only
> peers that can reach it directly will get in.
