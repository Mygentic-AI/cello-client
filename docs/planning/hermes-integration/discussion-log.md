# Discussion Log — Integrating CELLO with Hermes Agent

**Status:** Planning / design discussion. No implementation in this document.
**Date opened:** 2026-06-28
**Owner:** TBD
**Question:** How do we let the CELLO client work with [Hermes Agent](https://github.com/nousresearch/hermes-agent)
*easily*, ideally **without a pull request to Hermes**?

---

## 1. TL;DR

CELLO and Hermes already meet at one interface: **MCP (Model Context Protocol)**.

- `@cello-protocol/connect` ships a binary `cello-mcp` — a standard **stdio MCP server** that proxies
  `cello_*` tool calls to the local CELLO daemon over `~/.cello/daemon.sock`.
- Hermes consumes **external stdio MCP servers** declared in its config (`mcp_servers:` in
  `cli-config.yaml` / `~/.hermes/config.yaml`), auto-discovers their tools, and hot-reloads them
  with `/reload-mcp`.

So the integration is **operator configuration, not code**. No Hermes PR is required. The work on
our side is *documentation + enablement*, not protocol work.

The recommended deliverables (tracked, not built here) are:
1. An integration doc in this repo (install + `mcp_servers` recipe + gotchas + verification).
2. Filling the **empty** `core/adapter-claude-code/src/SKILL.md` so a Hermes agent knows the CELLO
   *session flow*, not just that tools exist.
3. (Optional) A small `cli` helper that emits the correct YAML for the user's `CELLO_DIR`.

---

## 2. What each side actually exposes

### 2.1 CELLO client (this repo)

- `@cello-protocol/connect` (package dir: `core/adapter-claude-code/`) ships `bin: { "cello-mcp": ... }`.
- `core/adapter-claude-code/src/bin/cello-mcp.ts` builds a `McpServer` over
  `StdioServerTransport` (`@modelcontextprotocol/sdk`). It is a **thin stdio→IPC proxy**: holds no key
  material, opens no DB, creates no libp2p node. All real work happens in the daemon.
- It connects to `${CELLO_DIR:-~/.cello}/daemon.sock`. If the socket is missing (`ENOENT` /
  `ECONNREFUSED`) it prints `daemon not running — run cello login` and exits 1.
- Tools registered (stable surface today):
  - Agent mgmt: `cello_start_agent`, `cello_set_agent_offline`, `cello_use_agent`, `cello_list_agents`
  - Sessions: `cello_initiate_session`, `cello_await_session`, `cello_send`, `cello_receive`,
    `cello_receive_session`, `cello_close_session`, `cello_list_sessions`
  - Status/receipts: `cello_status`, `cello_backup`, `cello_restore`, `cello_get_sealed_receipt`,
    `cello_get_transcript`, `cello_get_inclusion_proof`
- The blessed Claude Code wiring is literally `claude mcp add cello -- cello-mcp` (see the TTY help
  text in `cello-mcp.ts`).
- `core/adapter-claude-code/src/SKILL.md` exists in the published `files` list but is **currently a
  0-byte file** — a real gap (see §5).

### 2.2 Hermes Agent (external, no changes wanted)

From the Hermes docs/repo (read 2026-06-28):

- Repo layout includes `optional-mcps/`, `optional-skills/`, `skills/`, `tools/`, and a
  `cli-config.yaml.example`.
- `cli-config.yaml.example` documents an `mcp_servers:` block supporting:
  - **stdio servers**: `command`, `args`, `env` (only the listed `env` vars + safe defaults are passed
    to the subprocess).
  - **HTTP servers**: `url`, `headers`.
  - Per-server: `timeout` (120s), `connect_timeout` (60s), `keepalive_interval` (180s), optional
    `sampling:` block.
- "Tools from connected MCP servers are automatically discovered and registered for agent use."
- `/reload-mcp` (chat command) reloads MCP servers from config without a full restart.
- Hermes also has a **skills system** invoked via `/<skill-name>` and an `optional-skills/` drop-in
  directory — a second, PR-free integration vector.

---

## 3. Options considered

### Option A — Register `cello-mcp` as an external MCP server in Hermes  ✅ RECOMMENDED

Operator installs the npm packages, starts the daemon, and adds one `mcp_servers` entry.

```yaml
# ~/.hermes/config.yaml  (or cli-config.yaml)
mcp_servers:
  cello:
    command: cello-mcp
    # env:                      # ONLY required for a non-default home (see §4):
    #   CELLO_DIR: /path/to/.cello
```

```bash
npm install -g @cello-protocol/connect @cello-protocol/cli
cello login            # starts the daemon, creates ~/.cello/daemon.sock
# then /reload-mcp inside Hermes (or restart the gateway)
```

- **Pros:** zero Hermes code; uses the exact mechanism Hermes ships for third-party tools; mirrors the
  proven Claude Code path; survives Hermes upgrades; hot-reloadable.
- **Cons:** operator must do a 3-line setup; ordering + env-passing gotchas (§4); the agent still needs
  to *know how* to drive the tools (§5).

### Option B — Ship a Hermes "skill" alongside the MCP server  ✅ RECOMMENDED COMPLEMENT

Author a CELLO skill (markdown) that Hermes can drop into `optional-skills/` (or its skills dir). It
teaches the session lifecycle and references the `cello_*` tools. Pairs with Option A: A gives tools,
B gives procedure. Still no Hermes PR — skills are user-installable.

- **Pros:** turns "tools exist" into "agent runs a sealed session correctly"; reuses our existing (empty)
  `SKILL.md` artifact; no upstream change.
- **Cons:** another artifact to keep in sync with the tool surface.

### Option C — Contribute an entry under Hermes `optional-mcps/`  ❌ (violates the no-PR constraint)

`optional-mcps/` already contains `linear`, `n8n`, `unreal-engine`. We *could* add `cello/`. This is
the most discoverable for Hermes users but **requires a PR to Hermes**, which the requester explicitly
wants to avoid. Park as a possible *later* follow-up once Option A is proven; not the path now.

### Option D — HTTP MCP transport instead of stdio  ❌ (not how the shim works today)

Hermes supports `url:`-based MCP servers. `cello-mcp` is **stdio-only** and per-connection; there is no
HTTP listener. Building one would be real work on our side and changes the security surface (a network
listener vs. a local stdio child). No reason to do this for a single-machine agent. Rejected.

**Decision:** pursue **A + B**. Keep C as a future amplifier, D as out-of-scope.

---

## 4. Gotchas / risks to design around

1. **Daemon-before-MCP ordering.** Hermes spawns stdio MCP subprocesses at startup/reload. If the
   daemon isn't up, `cello-mcp` exits 1 and the `cello` server shows as failed. Mitigation: document
   "run `cello login` first, then `/reload-mcp`"; consider whether `cli` can offer a one-shot
   "ensure daemon running" used in setup docs.

2. **Env filtering is the sharp edge.** Hermes passes *only* the `env:` keys you list (plus safe
   defaults) into the subprocess. `cello-mcp` resolves its home from `CELLO_DIR`. So if the operator
   runs the daemon under a non-default `CELLO_DIR`, they **must** mirror it in the `mcp_servers.cello.env`
   block, or the shim looks in `~/.cello`, misses the socket, and fails with `daemon not running`. This
   is the most likely "it doesn't work" support ticket — call it out prominently and consider emitting
   it automatically (Option, §6 deliverable 3). Also verify `HOME` is among Hermes' "safe defaults";
   if not, it must be passed too.

3. **PATH / discoverability of `cello-mcp`.** `command: cello-mcp` requires the binary on the
   gateway's PATH. Global npm install handles the CLI case, but the **gateway runs as a service**
   (systemd/launchd) with a captured PATH snapshot. If `cello-mcp` is installed after the gateway
   service was created, the service PATH may not include it → document `hermes gateway install` re-run
   (macOS plists are static) or use an absolute `command:` path. Fallback form:
   `command: npx`, `args: ["-y", "-p", "@cello-protocol/connect", "cello-mcp"]`.

4. **Version pinning / publish invariants.** Per this repo's publishing rules, `connect` must be on
   `latest` and any `core/*` change cascades a version bump. The Hermes doc should pin a *minimum*
   `@cello-protocol/connect` version that includes the tool surface it describes, so a stale global
   install doesn't silently lack tools.

5. **Tool-surface drift.** If we add/rename `cello_*` tools, both the Hermes doc and the skill (§5)
   must be updated. A single source-of-truth list (generated from `cello-mcp.ts`?) would prevent drift —
   note as a nice-to-have, not blocking.

6. **Sampling / server-initiated LLM calls.** Hermes enables MCP "sampling" by default. `cello-mcp`
   does not initiate sampling today, so no action — but record it so a future CELLO feature that *does*
   use sampling is reviewed against Hermes' per-server `sampling:` caps.

7. **Security posture.** `cello-mcp` exposes session/keys-adjacent operations (via the daemon) to
   whatever agent loads it. Hermes' own allowlist/admin-tier model (deny-by-default) governs *who can
   talk to the bot*, but once in, MCP tools are available. Doc should remind operators that adding
   CELLO tools to a shared Hermes bot grants those users CELLO session capability.

---

## 5. The SKILL.md gap

`core/adapter-claude-code/src/SKILL.md` is published (it's in the package `files` list) but empty.
This matters for **both** Claude Code and Hermes: it's the procedural memory that turns a pile of
`cello_*` tools into a runnable flow. A good skill should cover:

- Preconditions: daemon running (`cello login`), an agent registered + started (`cello_start_agent`).
- Initiator flow: `cello_initiate_session(target_pubkey)` → `cello_send` / `cello_receive` loop →
  `cello_close_session` (seal ceremony) → `cello_get_sealed_receipt` / `cello_get_transcript`.
- Responder flow: `cello_await_session` → same send/receive loop → close.
- Recovery: `cello_get_transcript` is durable across daemon restarts.
- Error semantics: `daemon_not_running`, `ipc_connection_lost`, version mismatch.

Filling it is **implementation** and therefore out of scope for this log — but it is the single
highest-leverage follow-up, and it doubles as the basis for the Hermes skill (Option B).

---

## 6. Proposed plan (phated, for a later implementation pass)

> Documentation/enablement only — none of this changes the protocol or requires a Hermes PR.

- **Deliverable 1 — Integration doc** (e.g. `docs/integrations/hermes.md` or repo `HERMES.md`):
  install steps, the `mcp_servers` YAML, the env/`CELLO_DIR` gotcha, PATH-for-service note, minimum
  `connect` version, verification (`/reload-mcp` then call `cello_status`), troubleshooting table.
- **Deliverable 2 — Fill `SKILL.md`** (§5). Source of truth for the session flow; consumed by Claude
  Code today and reusable as the Hermes skill body.
- **Deliverable 3 — (Optional) `cli` helper**: e.g. `cello hermes-setup` that prints (or writes) the
  correct `mcp_servers.cello` block, auto-filling `env.CELLO_DIR` when non-default and the absolute
  `cello-mcp` path. Removes the §4.2 footgun entirely.
- **Deliverable 4 — (Future) Hermes `optional-mcps/cello/` PR** (Option C) once A+B are proven in the
  wild — explicitly *not* now, per the no-PR constraint.

**Suggested sequencing:** D2 (skill) → D1 (doc references the skill) → D3 (helper) → D4 (upstream).
Follows SPARC: the skill/doc is the Specification + Architecture of the operator contract before any
helper code is written (TDD applies to D3 only).

---

## 7. Open questions

1. Where should the operator doc live — repo root `HERMES.md`, `docs/integrations/hermes.md`, or the
   trustless-cello monorepo docs? (Discoverability vs. keeping client/server docs separate.)
2. Is `HOME` in Hermes' MCP-subprocess "safe defaults" set? Confirms whether §4.2 needs `HOME` too.
3. Do we want one CELLO skill shared by Claude Code + Hermes, or platform-specific variants? (Tool
   names are identical, so one shared skill is likely enough.)
4. Minimum `@cello-protocol/connect` version to pin in the doc — tie to the current published tag.
5. Should the `cli` helper *write* into `~/.hermes/config.yaml` (merge risk) or only *print* the block
   for the operator to paste? (Lean print-only to avoid clobbering user config.)

---

## 8. References

- `core/adapter-claude-code/src/bin/cello-mcp.ts` — the stdio MCP server / IPC proxy.
- `core/adapter-claude-code/package.json` — `bin: cello-mcp`, `@modelcontextprotocol/sdk` dep.
- `core/adapter-claude-code/src/SKILL.md` — currently empty (see §5).
- Hermes `cli-config.yaml.example` — `mcp_servers:` schema (stdio/http, env filtering, timeouts).
- Hermes docs: messaging gateway + MCP integration; `/reload-mcp`; `optional-mcps/`, `optional-skills/`.
- `.claude/CLAUDE.md` — publishing invariants (version cascade, `latest` requirement) relevant to §4.4.
