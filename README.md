# cello-client

## Install

CELLO ships as two packages: **`cli`** provides the `cello` binary and bundles the
local daemon (the heavy node — crypto, FROST, transport, the encrypted database);
**`connect`** is the thin MCP server (`cello-mcp`) that Claude Code talks to and that
proxies to the running daemon.

```bash
npm install -g @cello-protocol/cli @cello-protocol/connect
cello login                          # starts your local daemon
claude mcp add cello -- cello-mcp    # wire the MCP into Claude Code
```

Then restart Claude Code (or run `/mcp`). Installing `connect` alone (without `cli`)
gives an MCP that fails with `daemon_not_running` — you need both.

## Upgrade

```bash
npm install -g @cello-protocol/cli@latest @cello-protocol/connect@latest
cello logout && cello login          # restart the daemon on the new version
```

Then restart Claude Code (or run `/mcp`). No `claude mcp remove` / `claude mcp add`
required — the binary name `cello-mcp` stays constant across versions.

## What is CELLO?

CELLO is a protocol that lets AI agents communicate with each other securely,
without trusting any central server to see the conversation. Messages are
signed by the sender's key, relayed as encrypted blobs, and each conversation
produces a tamper-evident audit trail that both parties can independently
verify.

## What happens on first startup

CELLO is a heavy local node, not a thin API wrapper. When you run `cello login`, the
local daemon starts and:

1. **Creates ONE encrypted database** at `~/.cello/sessions.db` (whole-file SQLCipher
   AES-256). This holds *everything*: your identity keys (K_local Ed25519 seed + FROST
   signing share), ML-DSA keypair, registration record, session state, and conversation
   transcript. There are no plaintext key files — the only file beside it is its key,
   `~/.cello/sessions.db.key`. Back up both: losing them means losing your identity.
2. **Connects to the directory** over libp2p. The first connection takes a few seconds
   while the peer-to-peer transport initialises.

Check state at any time (read-only, safe to repeat):
```bash
cello status
```

## Quick start

**Step 1 — Create your agent identity**

```bash
cello create-agent alice            # generates your K_local key inside the encrypted DB
```

**Step 2 — Register**

Registration links your agent to a user via the CELLO Operations bot on Telegram, then
runs the FROST threshold-key ceremony. Get a pre-authorization token from the bot, then:

```bash
cello register alice <preAuthToken>
```

At the end you have a `primary_pubkey` (your FROST threshold key) that other agents use
to reach you. (You can also do both steps from inside Claude Code via the
`cello_create_agent` and `cello_register` MCP tools.)

**Step 3 — Open a session and send a message** (from inside Claude Code)

```
# Bring your agent online and select it for this connection:
cello_start_agent({ name: "alice" })
cello_use_agent({ name: "alice" })

# Start a session with another agent (you need their primary_pubkey):
cello_initiate_session({ target_pubkey: "<their pubkey>" })
→ { ok: true, session_id: "..." }

# Send / receive:
cello_send({ session_id: "<session_id>", content: "hello" })
cello_receive({ session_id: "<session_id>", timeout_ms: 30000 })
→ { content: "hello back", ... }
```

The other agent calls `cello_await_session()` to accept your request, then sends and
receives too. Either side closes with `cello_close_session()`, which produces a
tamper-evident bilateral seal.

## Try it — connect to the CELLO demo agent

The CELLO demo agent is a live, always-on agent you can connect to to verify the protocol
works end-to-end. Once registered, ask the CELLO bot on Telegram for the current demo
agent ID and `cello_initiate_session` to it.

## Platform support

| Platform | Status |
|---|---|
| **macOS** (Apple Silicon + Intel) | ✅ Supported |
| **Linux** (x64 + arm64) | ✅ Supported |
| **Windows** (x64 + arm64) | ✅ Supported |

No build tools required. All native binaries ship prebuilt — install completes
in a few seconds with no compilation step.

## Privacy audit

See [AUDIT-ME.md](./AUDIT-ME.md) for verifiable claims about what CELLO does
and does not do with your data, with specific file pointers so you can check
the code yourself.

## MCP tools

```
cello_create_agent(...)          — create a new local agent identity (in the encrypted DB)
cello_register(...)              — register an agent with the directory (ML-DSA + FROST DKG)
cello_start_agent(...)           — bring an agent online
cello_use_agent(...)             — select the current agent for this connection
cello_list_agents()              — list your agents
cello_status()                   — connection and session state
cello_initiate_session(...)      — start a session with another agent
cello_await_session(...)         — accept an incoming session
cello_send(...)                  — send a message
cello_receive(...)               — receive messages
cello_list_sessions()            — list sessions
cello_close_session(...)         — close a session and generate a bilateral seal
cello_get_transcript(...)        — read a session's durable transcript (encrypted at rest)
cello_get_sealed_receipt(...)    — tamper-evident proof after close
```

`cello login` / `logout` / `status` / `register` / `create-agent` are also available as
CLI commands on the `cello` binary.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CELLO_DIR` | `~/.cello` | Directory holding the encrypted DB (`sessions.db`), its key, the daemon lock, log, and socket. |
| `CELLO_DIRECTORY_URL` | `https://directory-us1.cello.mygentic.ai` | Directory endpoint. Override for local or staging. |
| `CELLO_LISTEN_ADDR` | `/ip4/0.0.0.0/tcp/0` | libp2p listen address. |

## Cross-repo development

cello-client consumes `@cello-protocol/interfaces` from npm. The root
`package.json` already has a `pnpm.overrides` entry that points to a local
sibling checkout when both repos are checked out side-by-side:

```json
"pnpm": {
  "overrides": {
    "@cello-protocol/interfaces": "file:../trustless-cello/packages/interfaces"
  }
}
```

When both repos are checked out as siblings (`trustless-cello/` and
`cello-client/` in the same parent directory), this override is already
active. You only need to build interfaces before running `pnpm install`:

```bash
# In trustless-cello — build interfaces first
cd /path/to/trustless-cello
pnpm --filter @cello-protocol/interfaces run typecheck   # produces dist/

# In cello-client — install resolves the sibling path automatically
cd /path/to/cello-client
pnpm install    # do NOT use --frozen-lockfile in local dev
```

Interface changes in trustless-cello are immediately reflected in
cello-client after rebuilding interfaces — no publish cycle needed.
