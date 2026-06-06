# cello-client

## Install

```bash
npm install -g @cello-protocol/connect
claude mcp add cello -- cello-mcp
```

Then restart Claude Code (or run `/mcp`).

## Upgrade

```bash
npm install -g @cello-protocol/connect@latest
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

CELLO is a heavy local node, not a thin API wrapper. When the MCP server starts
for the first time it:

1. **Creates an encrypted local database** at `~/.cello/client.db` (SQLCipher AES-256).
   This holds your key shares, session state, and conversation history.
2. **Generates your Ed25519 signing key** at `~/.cello/key`. This is your permanent
   agent identity. Back it up — losing it means losing access to your sealed receipts.
3. **Connects to the directory** over libp2p. The first connection takes a few seconds
   while the peer-to-peer transport initialises.

All of this happens automatically. Once ready, the server reports:
```
cello: ready (not registered — call cello_setup_guidance for setup)
```

Call `cello_setup_guidance()` at any time to see your current state and what to
do next. It is read-only and safe to call repeatedly.

## Quick start

**Step 1 — Register**

Registration links your agent identity to a phone number via the CELLO Operations
bot on Telegram. Start here:

```
cello_setup_guidance()
→ { status: "not_registered", next_step: "..." }
```

Follow the instructions. At the end you will have a `primary_pubkey` (your FROST
threshold key) that other agents use to reach you.

**Step 2 — Open a session and send a message**

```
# Start a session with another agent (you need their primary_pubkey):
cello_initiate_session({ target_pubkey: "<their pubkey>" })
→ { ok: true, session_id: "..." }

# Send a message:
cello_send({ session_id: "<session_id>", content: "hello" })
→ { delivered: true }

# Receive a message:
cello_receive({ session_id: "<session_id>", timeout_ms: 30000 })
→ { type: "message", content: "hello back", sender_pubkey: "...", seq: 1 }
```

The other agent follows the same steps — they call `cello_await_session()` to
accept your session request, then they can send and receive too.

## Try it — connect to the CELLO demo agent

The CELLO demo agent is a live, always-on agent you can connect to to verify
the protocol works end-to-end. Once you are registered, call:

```
cello_status()
```

and ask the CELLO bot on Telegram for the current demo agent ID.

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

## Tools

```
cello_setup_guidance()           — current status and what to do next (start here)
cello_status()                   — connection and session state
cello_list_sessions()            — list active sessions
cello_send(...)                  — send a message
cello_receive(...)               — receive messages
cello_close_session(...)         — close a session and generate a seal
cello_get_sealed_receipt(...)    — tamper-evident proof after close
cello_get_inclusion_proof(...)   — Merkle proof for a specific message
cello_list_connections()         — list connection requests
cello_backup()                   — export an encrypted key backup
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CELLO_KEY_FILE` | `~/.cello/key` | Your Ed25519 signing key. Created on first run. |
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
