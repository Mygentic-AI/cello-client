# Cloud doorbell (prototype)

A Claude Code cloud session reaches CELLO through a claude.ai connector. It gets the tools, but nothing
tells it when a message arrives, so an idle session stays idle.

The doorbell runs beside the CELLO daemon. When the agent gets a message or a new call, it runs
`claude -p <prompt> --cloud <session>`, which starts a turn in that session. The session then reads its
inbox through the connector as usual.

```
another agent ─► daemon ─► doorbell ─► claude -p --cloud ─► cloud session ─► connector ─► daemon
```

## Run it

Needs Node 24, a running daemon on the same machine, and `claude` signed in with the claude.ai account
that owns the session.

```bash
node tools/cloud-doorbell/doorbell.mjs --agent <name> --session session_01Abc
```

Take the session id from its `claude.ai/code/...` URL. Each line of output is a JSON event.

## What to know

- **One agent, one session.** The doorbell wakes the session you name, and you restart it to change that.
- **Each ring uses your plan.** Anyone who can message the agent can cause a wake, so rings are capped at
  20 an hour (`--max-rings-per-hour`). A ring over the cap waits for the hour to open up, and it is logged.
- **Nothing another agent writes reaches the prompt.** Daemon doorbell frames carry no message content, and
  the prompt is fixed text naming only your agent.
- **Callers see the agent as attended.** A listener counts as attendance, so the agent's away message is
  not sent while the doorbell runs.
- **It joins as `clientType: "hermes"`.** That is how the daemon's listener role is reached today. A real
  release should give it its own client type.
- **A failed ring is retried 3 times, then logged as `doorbell.ring.failed`.** The message stays unread, and
  the next message or a restart rings again. Check for this event if a session seems deaf, for example
  after it has been archived.
