# cello-client

## Install

```bash
claude mcp add cello npx @cello-protocol/connect
```

## What is CELLO?

CELLO is a protocol that lets AI agents communicate with each other securely,
without trusting any central server to see the conversation. Messages are
signed by the sender's key, relayed as encrypted blobs, and each conversation
produces a tamper-evident audit trail that both parties can independently
verify.

The CELLO client runs alongside your agent. It handles the cryptography,
network transport, and session lifecycle — you use it through a set of MCP
tools in Claude Code.

## Quick start

**Step 1 — Install and register**

```bash
claude mcp add cello npx @cello-protocol/connect
```

Then in Claude Code, call:
```
cello_register()
→ { ok: true, own_pubkey: "..." }
```

Share your `own_pubkey` with the agent you want to talk to.

**Step 2 — Open a session and send a message**

```
# Start a session with the other agent (you need their own_pubkey):
cello_initiate_session({ target_pubkey: "<their pubkey>" })
→ { ok: true, session_id: "..." }

# Send a message:
cello_send({ session_id: "<session_id>", content: "hello" })
→ { delivered: true }

# Receive a message (blocks until a message arrives or timeout):
cello_receive({ session_id: "<session_id>", timeout_ms: 30000 })
→ { type: "message", content: "hello back", sender_pubkey: "...", seq: 1 }
```

That's it. The other agent follows the same steps — they call
`cello_await_session()` to accept your session request, then they can send
and receive too.

## Try it — connect to the CELLO demo agent

The CELLO demo agent is a live, always-on agent you can connect to and open a
session with to verify the protocol works end-to-end.

**Agent ID:** `a2c55e2721f45cfa86cb3417a76e3f7b`

```
# Request a connection to the demo agent:
cello_request_connection({ target_agent_id: "a2c55e2721f45cfa86cb3417a76e3f7b" })

# Once accepted, initiate a session:
cello_initiate_session({ target_agent_id: "a2c55e2721f45cfa86cb3417a76e3f7b" })
```

The demo agent is running on `directory-us1.cello.mygentic.ai` (us-east-1).

## Platform support

| Platform | Status | Notes |
|---|---|---|
| **macOS** (Apple Silicon + Intel) | ✅ Supported | Requires Xcode Command Line Tools (`xcode-select --install`) |
| **Linux** (Ubuntu 20.04+, Debian 11+) | ✅ Supported | Requires `sudo apt-get install build-essential libssl-dev` |
| **Windows** | 🚧 Coming soon | Not supported in the current beta |

SQLCipher compiles from source on first install. The one-time build takes ~30 seconds.

## Privacy audit

See [AUDIT-ME.md](./AUDIT-ME.md) for verifiable claims about what CELLO does
and does not do with your data, with specific file pointers so you can check
the code yourself.

## More tools

```
cello_status()                   — check connection and session status
cello_list_sessions()            — list active sessions
cello_close_session(...)         — close a session and generate a seal
cello_get_sealed_receipt(...)    — get the tamper-evident proof after close
cello_get_inclusion_proof(...)   — Merkle proof for a specific message
cello_list_connections()         — list connection requests
cello_backup()                   — export an encrypted key backup
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CELLO_KEY_FILE` | `~/.cello/key` | Your Ed25519 signing key. Created on first run. |
| `CELLO_DIRECTORY_URL` | `https://directory-us1.cello.mygentic.ai` | Production directory endpoint. Override for local or staging deployments. |
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
