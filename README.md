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

## Cross-repo development (pnpm link)

cello-client consumes `@cello-protocol/interfaces` from npm. When you need
to develop server-side interfaces alongside client code simultaneously, use
`pnpm link` to override the npm resolution with your local trustless-cello
workspace:

```bash
# In trustless-cello — build interfaces and make it linkable
cd /path/to/trustless-cello/packages/interfaces
pnpm run typecheck      # builds dist/
pnpm link --global      # registers the package globally

# In cello-client — link to the local version
cd /path/to/cello-client
pnpm link --global @cello-protocol/interfaces
```

To unlink (go back to the npm version):
```bash
cd /path/to/cello-client
pnpm unlink @cello-protocol/interfaces
pnpm install           # restores the npm version
```

This workflow lets interface changes in trustless-cello be immediately
reflected in cello-client without a publish/install cycle.
