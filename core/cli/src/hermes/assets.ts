/**
 * HERMES-001 — file assets scaffolded by `cello bridge hermes`.
 *
 * These are the exact file contents written into the operator's Hermes Agent home
 * (default ~/.hermes). They are embedded as string constants because the published
 * CLI package ships only dist/ (see core/cli package.json "files") — a separate asset
 * directory would not survive npm packaging without build-pipeline changes.
 *
 * Design source: trustless-cello docs/planning/discussion_logs/
 * 2026-07-09_1915_hermes-agent-integration-plan.md §3–§5. The adapter mirrors the
 * shape of Hermes' bundled Raft platform adapter (hermes-agent
 * plugins/platforms/raft/adapter.py) minus every piece of bridge machinery that only
 * exists to cross a process/language boundary: CELLO's daemon speaks newline-delimited
 * JSON over a Unix socket, so a pure-stdlib asyncio client talks to it in-process —
 * no subprocess, no HTTP hop, no bridge token.
 */

/** Hermes plugin manifest — `~/.hermes/plugins/cello/plugin.yaml`. */
export const HERMES_PLUGIN_YAML = `name: cello
label: CELLO
kind: platform
version: 0.1.0
description: >
  CELLO trust-layer platform adapter for Hermes Agent. Connects to the local
  CELLO daemon over its Unix-socket IPC, binds this Hermes instance to one
  registered CELLO agent, and injects content-free wake hints when a session
  changes state or a message arrives. The agent reads and replies through the
  cello_* MCP tools - the adapter never touches message content.
author: cello-protocol
requires_env:
  - name: CELLO_AGENT_NAME
    description: "Registered CELLO agent this Hermes instance binds to - auto-enables the adapter when set"
    prompt: "CELLO agent name"
    password: false
    category: setting
`;

/**
 * The CELLO platform adapter — `~/.hermes/plugins/cello/__init__.py`.
 *
 * Python, stdlib-only. Runs inside the Hermes gateway process, where the
 * `gateway` package is already importable (the plugin loader imports this module
 * in-process). Speaks the daemon IPC protocol directly:
 *   request       {"id": str, "method": str, "params": {...}}\n
 *   response      {"id": str, "result": ...} | {"id": str, "error": {code,message,guidance}}
 *   notification  {"notification": str, "data": {...}}   (server-initiated, no id)
 * Handshake: ipc.connect {clientType} -> cello_use_agent {name} (binds notification
 * routing: session_state_changed / cello_message reach only connections whose
 * currentAgent matches — see daemon NotificationDispatcher).
 */
export const HERMES_PLUGIN_INIT_PY = String.raw`"""CELLO platform adapter for Hermes Agent.

Connects to the local CELLO daemon over its Unix-socket IPC (newline-delimited
JSON), binds this Hermes instance to one registered CELLO agent, and injects
content-free wake hints into the normal gateway session pipeline when a CELLO
session changes state or a message arrives. The agent itself reads and replies
through the cello_* MCP tools (the 'cello' entry in mcp_servers) - this adapter
never touches message content, and its send() is a deliberate no-op.

Installed and kept up to date by 'cello bridge hermes'. Do not edit in place;
re-run the installer to upgrade.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
    merge_pending_message_event,
)
from gateway.session import build_session_key

logger = logging.getLogger(__name__)

DEFAULT_RUNTIME_SESSION = "default"
# The two daemon notifications that mean "this agent's attention is needed".
# agent_state_changed / agent_current_changed are connection bookkeeping, not wakes.
WAKE_NOTIFICATIONS = {"session_state_changed", "cello_message"}
RECONNECT_INITIAL_DELAY = 1.0
RECONNECT_MAX_DELAY = 30.0
CALL_TIMEOUT_SECONDS = 30.0
# Matches the daemon IPC server's MAX_BUFFER_SIZE (4 MB).
MAX_LINE_BYTES = 4 * 1024 * 1024

# Same recursive content-free guard the Raft adapter applies to wake payloads.
# The daemon's INV-CONTENTFREE invariant means these keys never appear in a
# notification; if one does, something upstream is violating the protocol and
# the wake is dropped loudly rather than relayed.
_CONTENT_FIELD_NAMES = {
    "body",
    "content",
    "message",
    "messages",
    "preview",
    "snippet",
    "text",
}

# Pubkeys are base64/hex-ish, session ids are uuid-ish; anything outside this
# conservative charset (or overlong) renders as 'unknown' in the wake prompt.
_SAFE_SCALAR_RE = re.compile(r"^[A-Za-z0-9+/=_.:@-]{1,120}$")

# The protocol's moniker charset (core/protocol-types MONIKER_RE). Deliberately excludes spaces,
# quotes, parentheses and markup, so a fingerprint ("agent 77d0c806...") never matches and neither
# does anything that could restructure the wake sentence.
_MONIKER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _cello_socket_path() -> Path:
    cello_dir = os.environ.get("CELLO_DIR") or str(Path.home() / ".cello")
    return Path(cello_dir) / "daemon.sock"


def check_cello_requirements() -> bool:
    """Passive dependency probe (platform check_fn) - intentionally silent.

    Called on every gateway config load; the registry logs its own warning when
    requirements are unmet and the adapter is actually requested.
    """
    return _cello_socket_path().exists()


def _has_content_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).strip().lower() in _CONTENT_FIELD_NAMES:
                return True
            if _has_content_field(nested):
                return True
    elif isinstance(value, list):
        return any(_has_content_field(item) for item in value)
    return False


def _safe_scalar(value: Any, default: str = "unknown") -> str:
    if not isinstance(value, str) or not value:
        return default
    # fullmatch, never match: in Python a trailing '$' ALSO matches just before a final newline,
    # so re.match(r"^...$", "abc\n") succeeds where the daemon's JS equivalent rejects. A
    # re-validation layer that is laxer than the rule it mirrors is not a layer.
    if not _SAFE_SCALAR_RE.fullmatch(value):
        return default
    return value


def _render_who(data: Any) -> Optional[str]:
    """DOD-HERMES-3: the daemon-resolved counterparty label, or None.

    The daemon stamps who/whoKnown on both counterparty-bearing frames (MONIKER-4 AC2) with three
    tiers: the operator's own pet name, the caller's self-declared offered name, or a fingerprint.
    Only a NAME is rendered - the fingerprint tier ('agent 77d0c806...') is derived from the very
    pubkey every wake already carries in full, so echoing it is noise. A self-declared name is
    marked as a claim exactly as the Claude Code shim marks it, and the marker cannot be forged
    because MONIKER_RE excludes quotes and parentheses.

    The marker says the name came from its owner rather than from the operator. whoKnown is true
    only when the operator set a local pet name, so it appears for every contact they have not
    named - not only new ones. Nothing in the protocol ever verifies a name.

    Re-validated here rather than trusted: Hermes has no metadata layer, so this prose IS the frame
    (spec §11) and a name-shaped token is the only thing that may ever enter it.
    """
    # fullmatch, never match - see _safe_scalar. re.match would admit "CELLO_Support\n", putting a
    # newline into prose that IS the frame. Rejected whole; never stripped (§3: no mutation oracle).
    who = data.get("who") if isinstance(data, dict) else None
    if not isinstance(who, str) or not _MONIKER_RE.fullmatch(who):
        return None
    if data.get("whoKnown") is True:
        return who
    return '"' + who + '" (self-declared)'


class CelloAdapter(BasePlatformAdapter):
    """Wake-only adapter: daemon IPC notifications in, nothing out.

    Replies happen through the cello_* MCP tools as the agent's own tool
    actions - never through the gateway delivery pipeline - so send() is a
    no-op, exactly like the Raft adapter.
    """

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform("cello"))
        extra = config.extra or {}
        self._agent_name: str = str(
            extra.get("agent_name") or os.environ.get("CELLO_AGENT_NAME", "")
        ).strip()
        self._runtime_session: str = str(
            extra.get("runtime_session", DEFAULT_RUNTIME_SESSION)
            or DEFAULT_RUNTIME_SESSION
        )
        self._writer: Optional[asyncio.StreamWriter] = None
        self._read_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._pending: Dict[str, asyncio.Future] = {}
        self._next_id = 1
        self._closing = False

    # ------------------------------------------------------------------ lifecycle

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        if not self._agent_name:
            logger.error(
                "[cello] CELLO_AGENT_NAME is not set - cannot bind this Hermes "
                "instance to a CELLO agent. Run 'cello bridge hermes --agent <name>' "
                "or set CELLO_AGENT_NAME in the Hermes env file, then restart the gateway."
            )
            return False
        self._closing = False
        try:
            await self._establish()
        except Exception as exc:
            logger.error(
                "[cello] Could not connect to the CELLO daemon at %s: %s. "
                "Is the daemon running? Start it with 'cello login'.",
                _cello_socket_path(),
                exc,
            )
            # Suppress the read loop's auto-reconnect: a failed INITIAL connect must
            # report failure and stop, not keep retrying behind a False return.
            self._closing = True
            if self._read_task is not None and not self._read_task.done():
                self._read_task.cancel()
            await self._teardown_socket()
            return False
        self._mark_connected()
        logger.info(
            "[cello] Connected to the CELLO daemon; bound to agent '%s'",
            self._agent_name,
        )
        return True

    async def disconnect(self) -> None:
        self._closing = True
        for task in (self._read_task, self._reconnect_task):
            if task is not None and not task.done():
                task.cancel()
        self._read_task = None
        self._reconnect_task = None
        await self._teardown_socket()
        self._mark_disconnected()
        logger.info("[cello] Disconnected")

    async def _establish(self) -> None:
        """Open the socket, start the frame reader, and run the IPC handshake."""
        reader, writer = await asyncio.open_unix_connection(
            str(_cello_socket_path()), limit=MAX_LINE_BYTES
        )
        self._writer = writer
        self._read_task = asyncio.create_task(self._read_loop(reader))

        await self._call("ipc.connect", {"clientType": "hermes"})
        result = await self._call("cello_use_agent", {"name": self._agent_name})
        if isinstance(result, dict) and result.get("ok") is False:
            reason = str(result.get("reason", "unknown"))
            # agent_already_current means a previous connection for this agent is
            # simply still selected - a fine state to land in on reconnect.
            if reason != "agent_already_current":
                raise RuntimeError(
                    "cello_use_agent failed: "
                    + reason
                    + " - "
                    + str(result.get("guidance", ""))
                )
        if isinstance(result, dict) and result.get("warning"):
            # e.g. not_registered: selected and usable locally, but no directory
            # sessions until 'cello register-agent' - surface it, do not block the bind.
            logger.warning(
                "[cello] %s",
                result.get("warning_guidance") or result.get("warning"),
            )

    async def _teardown_socket(self) -> None:
        writer = self._writer
        self._writer = None
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self._fail_pending("connection closed")

    def _fail_pending(self, reason: str) -> None:
        pending = list(self._pending.values())
        self._pending.clear()
        for fut in pending:
            if not fut.done():
                fut.set_exception(ConnectionError(reason))

    async def _reconnect_forever(self) -> None:
        """Background retry after a lost daemon connection (e.g. daemon restart)."""
        delay = RECONNECT_INITIAL_DELAY
        while not self._closing:
            await asyncio.sleep(delay)
            try:
                await self._teardown_socket()
                await self._establish()
            except Exception as exc:
                logger.warning(
                    "[cello] Reconnect to the CELLO daemon failed (%s); retrying in %.0fs",
                    exc,
                    min(delay * 2, RECONNECT_MAX_DELAY),
                )
                delay = min(delay * 2, RECONNECT_MAX_DELAY)
                continue
            self._mark_connected()
            logger.info(
                "[cello] Reconnected to the CELLO daemon; agent '%s' re-bound",
                self._agent_name,
            )
            return

    # ------------------------------------------------------------------ IPC client

    async def _call(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = CALL_TIMEOUT_SECONDS,
    ) -> Any:
        writer = self._writer
        if writer is None:
            raise ConnectionError("IPC socket is not connected")
        req_id = str(self._next_id)
        self._next_id += 1
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[req_id] = fut
        frame = json.dumps({"id": req_id, "method": method, "params": params or {}})
        try:
            writer.write((frame + "\n").encode("utf-8"))
            await writer.drain()
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(req_id, None)

    async def _read_loop(self, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    frame = json.loads(stripped)
                except json.JSONDecodeError:
                    logger.warning(
                        "[cello] Malformed IPC frame (%d bytes) - skipped", len(stripped)
                    )
                    continue
                if not isinstance(frame, dict):
                    continue
                # Notification frames (server-initiated, no id) are checked FIRST and
                # never consume a pending request - mirrors cello-mcp's IpcProxy.
                if "notification" in frame:
                    try:
                        await self._on_notification(frame)
                    except Exception:
                        logger.exception("[cello] Failed to handle daemon notification")
                    continue
                fut = self._pending.pop(str(frame.get("id", "")), None)
                if fut is None or fut.done():
                    continue
                if "error" in frame:
                    err = frame.get("error") or {}
                    fut.set_result(
                        {
                            "ok": False,
                            "reason": err.get("code"),
                            "message": err.get("message"),
                            "guidance": err.get("guidance"),
                        }
                    )
                else:
                    fut.set_result(frame.get("result"))
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("[cello] IPC read loop crashed")
        finally:
            self._fail_pending("connection closed")
            # Spawn at most ONE reconnect loop: read tasks created by failed reconnect
            # attempts also land here when their socket is torn down, and must not
            # stack additional loops on top of the one already running.
            if not self._closing and (
                self._reconnect_task is None or self._reconnect_task.done()
            ):
                logger.warning(
                    "[cello] Lost the CELLO daemon connection - reconnecting in the background"
                )
                self._reconnect_task = asyncio.create_task(self._reconnect_forever())

    # ------------------------------------------------------------------ wake path

    async def _on_notification(self, frame: Dict[str, Any]) -> None:
        kind = str(frame.get("notification", ""))
        if kind not in WAKE_NOTIFICATIONS:
            logger.debug("[cello] Ignoring notification type '%s'", kind)
            return
        raw_data = frame.get("data")
        data: Dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        if _has_content_field(data):
            logger.error(
                "[cello] Dropping wake notification carrying a content field - "
                "INV-CONTENTFREE violation upstream (daemon must never push content)"
            )
            return
        if not self._message_handler:
            logger.warning(
                "[cello] Wake received before the gateway message handler was attached - dropped"
            )
            return
        source = self.build_source(
            chat_id=self._runtime_session,
            chat_name="CELLO",
            chat_type="dm",
            user_id="cello-daemon",
            user_name="CELLO",
        )
        event = MessageEvent(
            text=self._wake_prompt(kind, data),
            message_type=MessageType.TEXT,
            source=source,
            raw_message=data,
            message_id="cello-wake-" + uuid.uuid4().hex[:12],
            internal=True,
        )
        await self.handle_message(event)

    async def handle_message(self, event: MessageEvent) -> None:
        """Queue wake hints for a busy session instead of interrupting the turn."""
        if not self._message_handler:
            return
        session_key = build_session_key(
            event.source,
            group_sessions_per_user=self.config.extra.get("group_sessions_per_user", True),
            thread_sessions_per_user=self.config.extra.get("thread_sessions_per_user", False),
        )
        if session_key in self._active_sessions:
            logger.debug("[cello] Wake queued for busy session %s", session_key)
            merge_pending_message_event(self._pending_messages, session_key, event)
            return
        await super().handle_message(event)

    def _wake_prompt(self, kind: str, data: Dict[str, Any]) -> str:
        # Unlike Raft's hardcoded generic hint, surface the (content-free) metadata the
        # daemon pushes - session id, counterparty pubkey, state - so the agent can act
        # without an extra discovery round-trip. Message CONTENT is never present here.
        #
        # OBSERVED 2026-07-09: a woken agent handed "reply [SILENT] if no action is needed"
        # takes that exit every time. Six wakes, six [SILENT]s, ZERO tool calls - the Hermes
        # transcript shows a "CELLO wake..." user turn followed immediately by an assistant
        # turn of "[SILENT]", with nothing in between.
        # A MESSAGE-ARRIVAL wake is never a no-action event: a peer is blocked waiting on a
        # reply. So silence is offered ONLY on state-change wakes; the message path spells out
        # the mandatory steps and forbids silence.
        #
        # cello_use_agent must come FIRST. The cello MCP server holds its own daemon connection,
        # separate from this adapter's, and a freshly started one has no current agent. With more
        # than one agent online the daemon's sole-online fallback cannot resolve, so every other
        # cello_* call would fail with no_current_agent.
        session_id = _safe_scalar(data.get("session_id") or data.get("sessionId"))
        agent = self._agent_name
        if kind == "cello_message":
            sender = _safe_scalar(data.get("from"))
            # DOD-HERMES-3 AC1/AC2: the name LEADS, the pubkey rides beside it (spec §11).
            who = _render_who(data)
            origin = (
                "from " + who + " (counterparty pubkey " + sender + ")"
                if who is not None
                else "from counterparty pubkey " + sender
            )
            return (
                "CELLO wake: a new message arrived on session "
                + session_id
                + " "
                + origin
                + ". A peer is waiting on you. Message content is never pushed, so you must fetch"
                " it. Use the MCP tools named cello_* (from the 'cello' MCP server) - they are"
                " already available to you. Do NOT run the 'cello' command-line program, and do"
                " NOT restart anything. Do this now, in order: (1) call the cello_use_agent tool"
                " with name='"
                + agent
                + "'; (2) call the cello_receive tool with cello_session_id='"
                + session_id
                + "' to read the message; (3) reply with the cello_send tool on that same session"
                " unless the message genuinely needs no answer. cello_receive must precede"
                " cello_send or the daemon rejects the send with session_not_current."
                " Do NOT answer [SILENT] on a message wake - reading the message is not optional."
            )

        state = _safe_scalar(data.get("state"))
        counterparty = _safe_scalar(data.get("counterpartyPubkey"))
        who = _render_who(data)
        subject = (
            who + " (counterparty pubkey " + counterparty + ")"
            if who is not None
            else "counterparty pubkey " + counterparty
        )
        return (
            "CELLO wake: session "
            + session_id
            + " with "
            + subject
            + " changed state to '"
            + state
            + "'. This is a state notice, not a message. If it needs no action, reply with exactly"
            " [SILENT]. If you do need to act, call cello_use_agent with name='"
            + agent
            + "' first, then whichever cello_* tool you need."
        )

    # ------------------------------------------------------------------ outbound (no-op)

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        logger.debug(
            "[cello] adapter send is a no-op; the agent delivers via cello_send (MCP)"
        )
        return SendResult(success=True)

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"name": "cello/" + str(chat_id), "type": "cello"}


# ---------------------------------------------------------------------- registry

def _is_connected(config: PlatformConfig) -> bool:
    extra = config.extra or {}
    return bool(extra.get("enabled") or extra.get("agent_name"))


def _env_enablement() -> Optional[dict]:
    """Auto-enable the platform when CELLO_AGENT_NAME is set (Raft's RAFT_PROFILE pattern)."""
    if not os.getenv("CELLO_AGENT_NAME"):
        return None
    return {"enabled": True}


def interactive_setup() -> None:
    """Interactive 'hermes gateway setup' flow for the CELLO platform."""
    from hermes_cli.cli_output import (
        print_header,
        print_info,
        print_success,
        print_warning,
        prompt,
        prompt_yes_no,
    )
    from hermes_cli.config import get_env_value, save_env_value

    print_header("CELLO")
    existing = get_env_value("CELLO_AGENT_NAME")
    if existing:
        print_info("CELLO: already configured (agent: " + existing + ")")
        if not prompt_yes_no("Reconfigure CELLO?", False):
            print_info("Keeping CELLO_AGENT_NAME=" + existing + ".")
            return

    print_info("Bind this Hermes instance to a registered CELLO agent.")
    print_info("If you have not set up CELLO yet, run: cello login, then")
    print_info("cello create-agent <name> and cello register-agent <name> <token>.")
    print()

    agent = prompt("CELLO agent name", default=existing or "")
    if not agent:
        print_warning("CELLO agent name is required; skipping CELLO setup")
        return

    save_env_value("CELLO_AGENT_NAME", agent.strip())

    print()
    print_success("CELLO configuration saved")
    print_info("Restart the gateway for changes to take effect: hermes gateway restart")


def register(ctx) -> None:
    """Plugin entry point - called by the Hermes plugin system."""
    ctx.register_platform(
        name="cello",
        label="CELLO",
        adapter_factory=lambda cfg: CelloAdapter(cfg),
        check_fn=check_cello_requirements,
        is_connected=_is_connected,
        required_env=["CELLO_AGENT_NAME"],
        install_hint=(
            "Install the CELLO client and start its daemon: "
            "npx --yes @cello-protocol/cli@latest login "
            "(then 'cello bridge hermes --agent <name>')"
        ),
        setup_fn=interactive_setup,
        env_enablement_fn=_env_enablement,
        emoji="\U0001F3BB",
        platform_hint=(
            "You are connected to CELLO, a peer-to-peer identity and trust layer for "
            "agent-to-agent communication.\n"
            "\n"
            "HOW TO USE CELLO: exclusively through the MCP tools named cello_* , served by "
            "the MCP server called 'cello'. They are already available to you. Their names "
            "are cello_use_agent, cello_receive, cello_send, cello_inbox, "
            "cello_sessions, cello_close_session, cello_status, and others.\n"
            "\n"
            "NEVER run the 'cello' command-line program. It is not the way in, and running "
            "it from inside a turn spawns a daemon bound to your process that dies when your "
            "turn ends. NEVER run 'cello login', 'cello logout', or anything that restarts "
            "the CELLO daemon: a single daemon serves EVERY agent on this machine, so "
            "restarting it takes all of them offline and orphans every connected MCP server. "
            "Restarting is never the fix. If a cello_* tool returns an error, read the error, "
            "fix the cause, and retry the tool.\n"
            "\n"
            "Before any other cello_* call, select your agent with cello_use_agent "
            "(name='" + os.environ.get("CELLO_AGENT_NAME", "your-agent") + "'). The cello MCP "
            "server holds its own daemon connection with no agent selected, so other calls "
            "fail with no_current_agent until you do.\n"
            "\n"
            "Always read before you send: cello_receive on a session before cello_send, or "
            "the daemon rejects the send with session_not_current. Wake notices are "
            "content-free by design - fetch the actual message with cello_receive. A wake "
            "saying a MESSAGE ARRIVED is never a no-action event: a peer is waiting; read it "
            "and reply. Answer [SILENT] only for a state-change notice that genuinely needs "
            "nothing from you, never on a message wake."
        ),
    )
`;

/** The setup skill — `~/.hermes/skills/cello-bridge-setup/SKILL.md`. */
export const HERMES_SKILL_MD = `---
name: cello-bridge-setup
description: "Install and configure the CELLO agent-to-agent bridge for this Hermes instance."
version: 1.0.0
platforms: [linux, macos]
metadata:
  hermes:
    tags: [cello, messaging, integration, agent-to-agent]
    related_skills: []
---

# CELLO Bridge Setup

CELLO is a peer-to-peer identity and trust layer for agent-to-agent communication:
split-key signing, tamper-evident hash chains, and content-free wake notifications.
This skill wires the local CELLO daemon into Hermes so this agent can talk to other
CELLO agents anywhere.

Trigger: /cello-bridge-setup, or "install the CELLO bridge".

## Steps

1. **Check CELLO is set up.** Run \`cello status\`. If the CLI is missing or the daemon
   is not running, walk the user through CELLO onboarding first:
   \`npx --yes @cello-protocol/cli@latest login\`, then \`cello create-agent <name>\`,
   then \`cello register-agent <name> <pre-auth-token>\` (token from the CELLO Operations
   Agent on Telegram). Confirm with \`cello status\`.
2. **Pick the agent.** Ask the user which registered CELLO agent this Hermes instance
   should bind to (the \`cello status\` output lists them).
3. **Run the installer** — one command does all the work (plugin scaffold, env binding,
   \`hermes plugins enable cello\`, \`hermes mcp add cello\`):

       cello bridge hermes --agent <name>

   Pass \`--hermes-home <path>\` only if Hermes does not live at ~/.hermes.
4. **Restart the gateway:** \`hermes gateway restart\`.
5. **Verify.** Call the \`cello_status\` MCP tool and report the bound agent's state and
   \`standing_receiver_ready\`. The bridge is live when the agent shows online.

## How to operate CELLO (after setup)

- Wake notices from the CELLO platform are **content-free** — they name a session and a
  counterparty pubkey, never the message. Fetch content with \`cello_inbox\`
  and \`cello_receive\`.
- **Read before you send.** Call \`cello_receive\` on a session before \`cello_send\`; the
  daemon rejects out-of-cursor sends with \`session_not_current\`.
- If a wake needs no reply, answer with exactly \`[SILENT]\` and make no \`cello_send\` call.
`;
