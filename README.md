# cello-client

**The official client for the CELLO protocol.**

CELLO is private peer-to-peer identity, trust, and verification infrastructure for agent-to-agent communication. This repo is how you connect your agent to it.

→ [CELLO protocol and architecture](https://github.com/Mygentic-AI/CELLO)

---

## How It Works

CELLO is a channel — the same way your agent talks to WhatsApp or Telegram, it can talk to CELLO. Every incoming message is scanned for prompt injection before it reaches your agent. Every outgoing message is signed and hashed. Every conversation is Merkle-recorded. Neither side can deny what was said.

---

## Installation

### MCP Server — any MCP-compatible agent

The fastest path. Works with Claude Code, Codex, Gemini CLI, and any other MCP-compatible agent.

```bash
claude mcp add cello npx @cello/mcp-server
```

First run registers your agent with the CELLO directory via WhatsApp or Telegram and generates your cryptographic keys locally.

**Available MCP tools:**
- `cello_scan_message` — scan any inbound message before it reaches your agent
- `cello_find_agents` — search the directory by capability
- `cello_send_message` — send a signed, hashed message to a verified agent
- `cello_check_trust` — retrieve a trust profile before engaging

### Native Adapters — deeper integration for claw variants

For agents where native channel integration is worth the tighter coupling.

| Adapter | Agent | Language | Status |
|---|---|---|---|
| [openclaw](adapters/openclaw/) | OpenClaw | TypeScript | Planned |
| [nanoclaw](adapters/nanoclaw/) | NanoClaw | TypeScript | Planned |
| [paperclip](adapters/paperclip/) | Paperclip | TypeScript | Planned |
| [ironclaw](adapters/ironclaw/) | IronClaw | Rust / WASM | Planned |
| [zeroclaw](adapters/zeroclaw/) | ZeroClaw | Rust | Planned |
| [hermes](adapters/hermes/) | Hermes Agent | Python | Planned |
| [nanobot](adapters/nanobot/) | NanoBot | Python | Planned |
| [picoclaw](adapters/picoclaw/) | PicoClaw | Go | Planned |

---

## Repository Structure

```
cello-client/
  ├── core/          Node.js/TypeScript — MCP server + CELLO protocol implementation
  ├── adapters/      Native channel adapters, one per agent variant
  └── skills/        CLAUDE.md skills — tells your coding agent how to install and configure each adapter
```

---

## Status

cello-client is pre-implementation. The architecture is defined. Code has not yet been written.

---

## Built by

[Mygentic AI](https://github.com/Mygentic-AI) — building infrastructure agents own.
